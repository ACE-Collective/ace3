import base64
import json
import logging
import uuid
import warnings
from datetime import date, datetime
from typing import TYPE_CHECKING, Optional

import bcrypt
from flask_login import UserMixin
from sqlalchemy import (
    BINARY,
    BLOB,
    BOOLEAN,
    CHAR,
    DATE,
    DATETIME,
    TIMESTAMP,
    VARBINARY,
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    FetchedValue,
    ForeignKey,
    Index,
    Integer,
    PrimaryKeyConstraint,
    String,
    Text,
    UniqueConstraint,
    desc,
    func,
    select,
    text,
)
from sqlalchemy.dialects.mysql import (
    DATETIME as MYSQL_DATETIME,
    DOUBLE,
    ENUM as MYSQL_ENUM,
    INTEGER as MYSQL_INTEGER,
    LONGBLOB,
    MEDIUMTEXT,
    TINYINT,
)
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import (
    Mapped,
    aliased,
    mapped_column,
    reconstructor,
    relationship,
    validates,
)
from sqlalchemy.orm.session import Session
from werkzeug.security import check_password_hash as werkzeug_check_password_hash

from saq.analysis.analysis import Analysis
from saq.analysis.observable import Observable as _Observable
from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_config
from saq.constants import (
    DISPOSITION_DELIVERY,
    DISPOSITION_OPEN,
    DISPOSITION_REVIEW_UNREVIEWED,
    F_FILE,
    F_FQDN,
    F_URL,
    MAX_DETECTION_VALUE_LENGTH,
    QUEUE_DEFAULT,
)
from saq.database.meta import Base, BrocessBase, CacheBase, EmailArchiveBase
from saq.database.pool import get_db, get_db_connection
from saq.database.retry import execute_with_retry, retry
from saq.database.util.index import IndexSyncResult, sync_alert_index
from saq.disposition import get_dispositions
from saq.environment import get_global_runtime_settings
from saq.util import find_all_url_domains, validate_uuid
from saq.util.ui import get_tag_score

if TYPE_CHECKING:
    from saq.database.model.icon_configuration import IconConfiguration


def verify_password_hash(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash, supporting both werkzeug (legacy) and bcrypt formats."""
    if hashed_password.startswith("$2"):
        # Bcrypt hash ($2a$, $2b$, $2y$)
        return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())
    else:
        # Legacy werkzeug hash (pbkdf2, scrypt, etc.)
        return werkzeug_check_password_hash(hashed_password, plain_password)


def hash_password(plain_password: str) -> str:
    """Hash password using bcrypt."""
    return bcrypt.hashpw(plain_password.encode(), bcrypt.gensalt()).decode()


def new_alert_version() -> str:
    """Returns a fresh value for alerts.version -- an opaque token that is rotated every
    time anything about an alert changes (analysis tree, comments, disposition, ownership,
    event membership). API clients compare it between fetches instead of diffing the alert."""
    return str(uuid.uuid4())


class Alert(Base):

    @classmethod
    def create_from_root_analysis(cls, root_analysis: RootAnalysis) -> "Alert":
        return cls(
            uuid=root_analysis.uuid,
            storage_dir=root_analysis.storage_dir,
            location=root_analysis.location,
            company_id=root_analysis.company_id,
            event_time=root_analysis.event_time,
            tool=root_analysis.tool,
            tool_instance=root_analysis.tool_instance,
            alert_type=root_analysis.alert_type,
            description=root_analysis.description,
            queue=root_analysis.queue,
        )

    def _initialize(self):
        # when we lock the Alert this is the UUID we used to lock it with
        self.lock_uuid = str(uuid.uuid4())

        self._observable_open_event_counts = None

        # this is the RootAnalysis object that this Alert is associated with
        self._root_analysis: Optional[RootAnalysis] = None

        # when True, calling load() logs an ERROR with a stack trace
        self._log_error_on_load = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._initialize()

    @property
    def root_analysis(self) -> RootAnalysis:
        if self._root_analysis is None:
            self.load()

            if self._root_analysis is None:
                raise RuntimeError(f"failed to load root analysis for alert {self.uuid}")

        return self._root_analysis

    @reconstructor
    def init_on_load(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._initialize()

    def set_log_error_on_load(self, value=True):
        """Sets the log_error_on_load flag, propagated to the RootAnalysis on load()."""
        assert isinstance(value, bool)
        self._log_error_on_load = value

    def load(self):
        self._root_analysis = RootAnalysis(storage_dir=self.storage_dir)
        self._root_analysis.set_log_error_on_load(self._log_error_on_load)
        return self._root_analysis.load()

    def attach_root_analysis(self, root_analysis: RootAnalysis):
        """Attaches an already-loaded RootAnalysis instead of reading one from disk.

        The engine holds the live tree it just finished analyzing, so having sync() call
        load() would parse the entire data.json into a second RootAnalysis only to
        re-serialize that copy straight back out. The caller is responsible for checking
        that the root actually belongs to this alert (matching storage_dir).
        """
        assert isinstance(root_analysis, RootAnalysis)
        self._root_analysis = root_analysis

    __tablename__ = 'alerts'
    __table_args__ = (
        Index('idx_location', 'location', mysql_length=767),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True)

    company_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey('company.id', ondelete='CASCADE', onupdate='CASCADE'),
        nullable=True,
        index=True)

    company: Mapped[Optional["Company"]] = relationship('Company', foreign_keys=[company_id])

    uuid: Mapped[str] = mapped_column(
        String(36),
        unique=True,
        nullable=False)

    # rotated on every change to the alert; see new_alert_version() and
    # saq.database.util.alert.touch_alerts()
    # No server default: MySQL rejects DEFAULT (UUID()) as replication-unsafe DDL under
    # binlog + GTID, so a raw INSERT INTO alerts has to supply its own version.
    version: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        default=new_alert_version)

    location: Mapped[str] = mapped_column(
        String(1024),
        unique=False,
        nullable=False)

    storage_dir: Mapped[str] = mapped_column(
        String(512),
        nullable=False)

    insert_date: Mapped[datetime] = mapped_column(
        TIMESTAMP,
        nullable=False,
        index=True,
        server_default=text('CURRENT_TIMESTAMP'))

    event_time: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP,
        nullable=True)

    tool: Mapped[str] = mapped_column(
        String(256),
        nullable=False)

    tool_instance: Mapped[str] = mapped_column(
        String(1024),
        nullable=False)

    alert_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True)

    description: Mapped[Optional[str]] = mapped_column(
        String(1024),
        nullable=True)

    priority: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text('0'))

    disposition: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        default=DISPOSITION_OPEN,
        server_default=text("'OPEN'"))

    queue: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        default=QUEUE_DEFAULT,
        server_default=text("'default'"))

    disposition_user_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        index=True)

    disposition_time: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP,
        nullable=True)

    owner_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        index=True)

    owner_time: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP,
        nullable=True)

    archived: Mapped[bool] = mapped_column(
        BOOLEAN,
        nullable=False,
        default=False,
        server_default=text('0'))

    removal_user_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        index=True)

    removal_time: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP,
        nullable=True)

    # disposition review tracking
    # records whether a senior analyst has reviewed the disposition and the result of that review
    disposition_review: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        default=DISPOSITION_REVIEW_UNREVIEWED,
        server_default=text("'UNREVIEWED'"))

    review_user_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        index=True)

    review_time: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP,
        nullable=True)

    # when a disposition is corrected these preserve the original (incorrect) disposition and who set it
    incorrect_disposition: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True)

    incorrect_disposition_user_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        index=True)

    incorrect_disposition_time: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP,
        nullable=True)

    # blueprint icons are a legacy feature that is not commonly used anymore
    icon_blueprint_name: Mapped[Optional[str]] = mapped_column(
        String(256),
        nullable=True)

    icon_blueprint_path: Mapped[Optional[str]] = mapped_column(
        String(1024),
        nullable=True)

    # full url to an icon image to use for this alert
    # can also be a data url
    icon_url: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True)

    # relationships
    disposition_user: Mapped[Optional["User"]] = relationship(
        'User', primaryjoin='Alert.disposition_user_id == User.id', foreign_keys=[disposition_user_id])
    owner: Mapped[Optional["User"]] = relationship(
        'User', primaryjoin='Alert.owner_id == User.id', foreign_keys=[owner_id])
    remover: Mapped[Optional["User"]] = relationship(
        'User', primaryjoin='Alert.removal_user_id == User.id', foreign_keys=[removal_user_id])
    review_user: Mapped[Optional["User"]] = relationship(
        'User', primaryjoin='Alert.review_user_id == User.id', foreign_keys=[review_user_id])
    incorrect_disposition_user: Mapped[Optional["User"]] = relationship(
        'User', primaryjoin='Alert.incorrect_disposition_user_id == User.id', foreign_keys=[incorrect_disposition_user_id])
    tag_mappings: Mapped[list["TagMapping"]] = relationship('TagMapping', passive_deletes=True, passive_updates=True, lazy='joined', overlaps="tag_mapping")

    def get_observables(self):
        query = get_db().query(Observable)
        query = query.join(ObservableMapping, Observable.id == ObservableMapping.observable_id)
        query = query.join(Alert, ObservableMapping.alert_id == Alert.id)
        query = query.filter(Alert.uuid == self.uuid)
        query = query.group_by(Observable.id)
        return query.all()

    # XXX revist this weird thing -- no idea why this is designed like this
    def get_remediation_targets(self):
        # XXX hack to get around circular import - probably need to merge some modules into one
        from saq.observables import create_observable
        return []

        # get observables for this alert
        observables = self.get_observables()

        # get remediation targets for each observable
        targets = {}
        for o in observables:
            observable = create_observable(o.type, o.display_value)
            # create observable returns none if the value is bad for the type (e.g. 123 is not a valid ipv4)
            if observable is None:
                continue
            observable.alert = self
            for target in observable.remediation_targets:
                targets[target.id] = target

        # return sorted list of targets
        targets = list(targets.values())
        targets.sort(key=lambda x: f"{x.type}|{x.value}")
        return targets

    def get_remediation_status(self):
        targets = self.get_remediation_targets()
        remediations = []
        for target in targets:
            if len(target.history) > 0:
                remediations.append(target.history[0])

        if len(remediations) == 0:
            return 'new'

        s = 'success'
        for r in remediations:
            if not r.successful:
                return 'failed'
            if r.status != 'COMPLETED':
                s = 'processing'
        return s

    @property
    def wiki(self) -> str:
        return ''

    @property
    def observable_open_event_counts(self):
        """
        Returns a dictionary containing the open events as the keys and the number of observables in this alert
        that are also in alerts in the event.

        {<event>: # of observables in this alert that are also in the event}
        """
        return {}

        if self._observable_open_event_counts is None:
            results = {}

            # Skip file observables. The calculations will consider their hash observables instead.
            for observable in [o for o in self.root_analysis.observable_store.values() if o.type != F_FILE]:
                if 'OPEN' in observable.matching_events_by_status:
                    for event in observable.matching_events_by_status['OPEN']:
                        if event not in results:
                            results[event] = 0

                        results[event] += 1

            self._observable_open_event_counts = results

        return self._observable_open_event_counts

    @property
    def remediation_status(self):
        if not self.observable_mappings:
            return ''

        remediations = []
        for om in self.observable_mappings:
            for orm in om.observable.observable_remediation_mappings:
                remediations.append(orm.remediation)

        if len(remediations) == 0:
            return 'new'

        s = 'success'
        for rem in remediations:
            if not rem.successful:
                return 'failed'
            if rem.status != 'COMPLETED':
                s = 'processing'
        return s

    @property
    def remediation_targets(self):
        return self._remediation_targets if hasattr(self, '_remediation_targets') else self.get_remediation_targets()

    @property
    def all_email_analysis(self) -> list[Analysis]:
        from saq.modules.email import EmailAnalysis
        observables = self.root_analysis.find_observables(lambda o: o.get_analysis(EmailAnalysis))
        return [o.get_analysis(EmailAnalysis) for o in observables]

    @property
    def has_email_analysis(self) -> bool:
        from saq.modules.email import EmailAnalysis
        return bool(self.root_analysis.find_observable(lambda o: o.get_analysis(EmailAnalysis)))

    @property
    def has_renderer_screenshot(self) -> bool:
        # XXX needs to be updated
        return False

    @property
    def screenshots(self) -> list[dict]:
        return [
            {'alert_id': self.uuid, 'observable_id': o.id, 'scaled_width': o.scaled_width, 'scaled_height': o.scaled_height}
            for o in self.all_observables
            if (
                    o.type == F_FILE
                    and o.is_image
                    and o.file_name.startswith('renderer_')
                    and o.file_name.endswith('.png')
            )
        ]

    @validates('description')
    def validate_description(self, key, value):
        max_length = getattr(self.__class__, key).prop.columns[0].type.length
        if value and len(value) > max_length:
            return value[:max_length]
        return value


    def archive(self, *args, **kwargs):
        if self.archived is True:
            logging.warning(f"called archive() on {self} but already archived")
            return None

        result = self.root_analysis.archive(*args, **kwargs)
        self.archived = True
        self.version = new_alert_version()
        return result


    @hybrid_property
    def detection_count(self):
        return len(self.detection_points)

    @detection_count.expression
    def detection_count(cls):
        return (
            select(func.count(DetectionPoint.id))
            .where(DetectionPoint.alert_id == cls.id)
            .correlate_except(DetectionPoint)
            .scalar_subquery())

    @property
    def status(self):
        if self.lock is not None:
            return 'Analyzing ({})'.format(self.lock.lock_owner)

        if self.delayed_analysis is not None:
            return 'Delayed ({})'.format(self.delayed_analysis.analysis_module)
    
        if self.workload is not None:
            return 'New'

        # XXX this kind of sucks -- find a different way to do this
        if self.removal_time is not None:
            return 'Completed (Removed)'

        return 'Completed'


    @property
    def sorted_tags(self):
        tags = {}
        for tag_mapping in self.tag_mappings:
            tags[tag_mapping.tag.name] = tag_mapping.tag
        return sorted([x for x in tags.values()], key=lambda x: (-get_tag_score(x.name), x.name.lower()))

    # we also save these database properties to the JSON data

    KEY_DATABASE_ID = 'database_id'
    KEY_VERSION = 'version'
    KEY_PRIORITY = 'priority'
    KEY_INSERT_DATE = 'insert_date'
    KEY_DISPOSITION = 'disposition'
    KEY_DISPOSITION_USER_ID = 'disposition_user_id'
    KEY_DISPOSITION_TIME = 'disposition_time'
    KEY_OWNER_ID = 'owner_id'
    KEY_OWNER_TIME = 'owner_time'
    KEY_REMOVAL_USER_ID = 'removal_user_id'
    KEY_REMOVAL_TIME = 'removal_time'
    KEY_DISPOSITION_REVIEW = 'disposition_review'
    KEY_REVIEW_USER_ID = 'review_user_id'
    KEY_REVIEW_TIME = 'review_time'
    KEY_INCORRECT_DISPOSITION = 'incorrect_disposition'
    KEY_INCORRECT_DISPOSITION_USER_ID = 'incorrect_disposition_user_id'
    KEY_INCORRECT_DISPOSITION_TIME = 'incorrect_disposition_time'

    @property
    def json(self):
        """The full alert as JSON: the RootAnalysis tree (loaded on demand) plus this row's database state."""
        result = self.root_analysis.json
        result.update({
            Alert.KEY_DATABASE_ID: self.id,
            Alert.KEY_VERSION: self.version,
            Alert.KEY_PRIORITY: self.priority,
            Alert.KEY_INSERT_DATE: self.insert_date,
            Alert.KEY_DISPOSITION: self.disposition,
            Alert.KEY_DISPOSITION_USER_ID: self.disposition_user_id,
            Alert.KEY_DISPOSITION_TIME: self.disposition_time,
            Alert.KEY_OWNER_ID: self.owner_id,
            Alert.KEY_OWNER_TIME: self.owner_time,
            Alert.KEY_REMOVAL_USER_ID: self.removal_user_id,
            Alert.KEY_REMOVAL_TIME: self.removal_time,
            Alert.KEY_DISPOSITION_REVIEW: self.disposition_review,
            Alert.KEY_REVIEW_USER_ID: self.review_user_id,
            Alert.KEY_REVIEW_TIME: self.review_time,
            Alert.KEY_INCORRECT_DISPOSITION: self.incorrect_disposition,
            Alert.KEY_INCORRECT_DISPOSITION_USER_ID: self.incorrect_disposition_user_id,
            Alert.KEY_INCORRECT_DISPOSITION_TIME: self.incorrect_disposition_time
        })
        return result

    @json.setter
    def json(self, value):
        assert isinstance(value, dict)
        RootAnalysis.json.fset(self, value)

        if not self.id and Alert.KEY_DATABASE_ID in value:
            self.id = value[Alert.KEY_DATABASE_ID]

        if not self.disposition and Alert.KEY_DISPOSITION in value:
            self.disposition = value[Alert.KEY_DISPOSITION]

        if not self.disposition_user_id and Alert.KEY_DISPOSITION_USER_ID in value:
            self.disposition_user_id = value[Alert.KEY_DISPOSITION_USER_ID]

        if not self.disposition_time and Alert.KEY_DISPOSITION_TIME in value:
            self.disposition_time = value[Alert.KEY_DISPOSITION_TIME]

        if not self.owner_id and Alert.KEY_OWNER_ID in value:
            self.owner_id = value[Alert.KEY_OWNER_ID]

        if not self.owner_time and Alert.KEY_OWNER_TIME in value:
            self.owner_time = value[Alert.KEY_OWNER_TIME]

        if not self.removal_user_id and Alert.KEY_REMOVAL_USER_ID in value:
            self.removal_user_id = value[Alert.KEY_REMOVAL_USER_ID]

        if not self.removal_time and Alert.KEY_REMOVAL_TIME in value:
            self.removal_time = value[Alert.KEY_REMOVAL_TIME]

        if (not self.disposition_review or self.disposition_review == DISPOSITION_REVIEW_UNREVIEWED) and Alert.KEY_DISPOSITION_REVIEW in value and value[Alert.KEY_DISPOSITION_REVIEW]:
            self.disposition_review = value[Alert.KEY_DISPOSITION_REVIEW]

        if not self.review_user_id and Alert.KEY_REVIEW_USER_ID in value:
            self.review_user_id = value[Alert.KEY_REVIEW_USER_ID]

        if not self.review_time and Alert.KEY_REVIEW_TIME in value:
            self.review_time = value[Alert.KEY_REVIEW_TIME]

        if not self.incorrect_disposition and Alert.KEY_INCORRECT_DISPOSITION in value:
            self.incorrect_disposition = value[Alert.KEY_INCORRECT_DISPOSITION]

        if not self.incorrect_disposition_user_id and Alert.KEY_INCORRECT_DISPOSITION_USER_ID in value:
            self.incorrect_disposition_user_id = value[Alert.KEY_INCORRECT_DISPOSITION_USER_ID]

        if not self.incorrect_disposition_time and Alert.KEY_INCORRECT_DISPOSITION_TIME in value:
            self.incorrect_disposition_time = value[Alert.KEY_INCORRECT_DISPOSITION_TIME]

    def apply_icon_configuration(self, icon_configuration: Optional["IconConfiguration"]):
        """Mirrors an IconConfiguration into the icon_* columns, writing only changed columns."""
        if icon_configuration and icon_configuration.blueprint_file_location:
            name = icon_configuration.blueprint_file_location.name
            path = icon_configuration.blueprint_file_location.path
        else:
            name = path = None

        url = icon_configuration.url if icon_configuration else None

        if self.icon_blueprint_name != name:
            self.icon_blueprint_name = name
        if self.icon_blueprint_path != path:
            self.icon_blueprint_path = path
        if self.icon_url != url:
            self.icon_url = url

    @retry
    def sync(self, build_index=True):
        """Saves the Alert to disk and database."""
        assert self.storage_dir is not None # requires a valid storage_dir at this point
        assert isinstance(self.storage_dir, str)


        if self.root_analysis:
            self.root_analysis.save()

        # mirror the icon configuration from the root analysis extensions into the
        # icon_* columns so the management screen can render it without load()
        from saq.gui.icon import IconConfiguration, KEY_ICON_CONFIGURATION
        icon_configuration_dict = (self.root_analysis.extensions or {}).get(KEY_ICON_CONFIGURATION)
        icon_configuration = IconConfiguration.model_validate(icon_configuration_dict) if icon_configuration_dict else None
        self.apply_icon_configuration(icon_configuration)

        # anything that reaches sync() may have changed the tree, so rotate the version
        # unconditionally -- a spurious rotation only costs a client one re-fetch
        self.version = new_alert_version()

        # save the alert to the database
        session = Session.object_session(self)
        if session is None:
            session = get_db()()
        
        session.add(self)
        session.commit()
        if build_index:
            self.build_index()

        return True

    def is_locked(self):
        """Returns True if this Alert has already been locked."""
        with get_db_connection() as db:
            c = db.cursor()
            c.execute("""SELECT uuid FROM locks WHERE uuid = %s AND TIMESTAMPDIFF(SECOND, lock_time, NOW()) < %s""", 
                     (self.uuid, get_global_runtime_settings().lock_timeout_seconds))
            return c.fetchone() is not None

    def build_index(self) -> IndexSyncResult:
        """Reconciles this Alert's rows in the observables, tags, observable_mapping,
        tag_mapping, observable_tag_index and detection_points tables."""
        return self.rebuild_index()

    def rebuild_index(self) -> IndexSyncResult:
        """Reconciles this Alert's index rows with its analysis tree, writing only what
        changed since the last call.

        The diff is computed against the database.
        """
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with get_db_connection() as db:
                c = db.cursor()
                return execute_with_retry(db, c, self._rebuild_index)

    def _rebuild_index(self, db, c) -> IndexSyncResult:
        result = sync_alert_index(c, self.id, self.root_analysis)
        db.commit()

        if result.changed:
            logging.info("rebuilt index for %s: %s", self, result)
        else:
            logging.debug("index unchanged for %s", self)

        return result

    @property
    def node_location(self):
        return self.nodes.location

def load_alert(uuid: str) -> Optional[Alert]:
    """Returns the loaded Alert given by uuid, or None if the alert does not exist."""
    alert = get_db().query(Alert).filter(Alert.uuid == uuid).one_or_none()

    if alert:
        alert.load()

    return alert

def load_alert_by_storage_dir(storage_dir: str) -> Optional[Alert]:
    """Returns the loaded Alert given by storage_dir, or None if the alert does not exist."""
    alert = get_db().query(Alert).filter(Alert.storage_dir == storage_dir).one_or_none()

    if alert:
        alert.load()

    return alert

class Campaign(Base):
    __tablename__ = 'campaign'
    id: Mapped[int] = mapped_column(Integer, nullable=False, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)

class Company(Base):

    __tablename__ = 'company'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)

    @property
    def json(self):
        return {
            'id': self.id,
            'name': self.name }

class Config(Base):

    __tablename__ = 'config'

    key: Mapped[str] = mapped_column(String(512), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)

class DelayedAnalysis(Base):

    __tablename__ = 'delayed_analysis'
    __table_args__ = (
        Index('idx_node_delayed_until', 'node_id', 'delayed_until'),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True)

    uuid: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True)

    observable_uuid: Mapped[str] = mapped_column(
        CHAR(36),
        nullable=False)

    analysis_module: Mapped[str] = mapped_column(
        String(512),
        nullable=False)

    insert_date: Mapped[datetime] = mapped_column(
        DATETIME,
        nullable=False)

    delayed_until: Mapped[Optional[datetime]] = mapped_column(
        DATETIME,
        nullable=True)

    node_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('nodes.id', ondelete='CASCADE', onupdate='CASCADE'),
        nullable=False,
        index=True)

    storage_dir: Mapped[str] = mapped_column(
        String(1024),
        unique=False,
        nullable=False)


class EventStatus(Base):
    __tablename__ = 'event_status'

    id: Mapped[int] = mapped_column(Integer, nullable=False, primary_key=True)
    value: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)

class EventRemediation(Base):
    __tablename__ = 'event_remediation'

    id: Mapped[int] = mapped_column(Integer, nullable=False, primary_key=True)
    value: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)

class EventVector(Base):
    __tablename__ = 'event_vector'

    id: Mapped[int] = mapped_column(Integer, nullable=False, primary_key=True)
    value: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)

class EventRiskLevel(Base):
    __tablename__ = 'event_risk_level'

    id: Mapped[int] = mapped_column(Integer, nullable=False, primary_key=True)
    value: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)

class EventPreventionTool(Base):
    __tablename__ = 'event_prevention_tool'

    id: Mapped[int] = mapped_column(Integer, nullable=False, primary_key=True)
    value: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)

class EventType(Base):
    __tablename__ = 'event_type'

    id: Mapped[int] = mapped_column(Integer, nullable=False, primary_key=True)
    value: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)

class Event(Base):
    __tablename__ = 'events'
    __table_args__ = (
        UniqueConstraint('creation_date', 'name', name='creation_date'),
    )

    id: Mapped[int] = mapped_column(Integer, nullable=False, primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    creation_date: Mapped[date] = mapped_column(DATE, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped["EventStatus"] = relationship('EventStatus')
    status_id: Mapped[int] = mapped_column(Integer, ForeignKey('event_status.id'), nullable=False)
    remediation: Mapped["EventRemediation"] = relationship('EventRemediation')
    remediation_id: Mapped[int] = mapped_column(Integer, ForeignKey('event_remediation.id'), nullable=False)
    comment: Mapped[Optional[str]] = mapped_column(Text)
    vector: Mapped["EventVector"] = relationship('EventVector', lazy='joined')
    vector_id: Mapped[int] = mapped_column(Integer, ForeignKey('event_vector.id'), nullable=False)
    risk_level: Mapped["EventRiskLevel"] = relationship('EventRiskLevel')
    risk_level_id: Mapped[int] = mapped_column(Integer, ForeignKey('event_risk_level.id'), nullable=False)
    prevention_tool: Mapped["EventPreventionTool"] = relationship('EventPreventionTool')
    prevention_tool_id: Mapped[int] = mapped_column(Integer, ForeignKey('event_prevention_tool.id'), nullable=False)
    campaign_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey('campaign.id'), nullable=True)
    campaign: Mapped[Optional["Campaign"]] = relationship('Campaign', foreign_keys=[campaign_id])
    type: Mapped["EventType"] = relationship('EventType', lazy='joined')
    type_id: Mapped[int] = mapped_column(Integer, ForeignKey('event_type.id'), nullable=False)
    malware: Mapped[list["MalwareMapping"]] = relationship('MalwareMapping', passive_deletes=True, passive_updates=True)
    alert_mappings: Mapped[list["EventMapping"]] = relationship('EventMapping', back_populates='event', passive_deletes=True, passive_updates=True)
    companies: Mapped[list["CompanyMapping"]] = relationship('CompanyMapping', passive_deletes=True, passive_updates=True)
    event_time: Mapped[Optional[datetime]] = mapped_column(DATETIME, nullable=True)
    alert_time: Mapped[Optional[datetime]] = mapped_column(DATETIME, nullable=True)
    ownership_time: Mapped[Optional[datetime]] = mapped_column(DATETIME, nullable=True)
    disposition_time: Mapped[Optional[datetime]] = mapped_column(DATETIME, nullable=True)
    contain_time: Mapped[Optional[datetime]] = mapped_column(DATETIME, nullable=True)
    remediation_time: Mapped[Optional[datetime]] = mapped_column(DATETIME, nullable=True)
    owner_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey('users.id'), nullable=True)
    owner: Mapped[Optional["User"]] = relationship('User', foreign_keys=[owner_id])

    @property
    def json(self):
        return {
            'id': self.id,
            'uuid': self.uuid,
            'alerts': self.alerts,
            'alert_versions': self.alert_versions,
            'alert_details': self.alert_details,
            'campaign': self.campaign.name if self.campaign else None,
            'comment': self.comment,
            'companies': self.company_names,
            'creation_date': str(self.creation_date),
            'event_time': str(self.event_time),
            'alert_time': str(self.alert_time),
            'ownership_time': str(self.ownership_time),
            'disposition_time': str(self.disposition_time),
            'contain_time': str(self.contain_time),
            'remediation_time': str(self.remediation_time),
            'disposition': self.disposition,
            'malware': [{mal.name: [t.threat_type.name for t in mal.threats]} for mal in self.malware],
            'name': self.name,
            'prevention_tool': self.prevention_tool.value,
            'remediation': self.remediation.value,
            'risk_level': self.risk_level.value,
            'status': self.status.value,
            'tags': self.sorted_tags,
            'type': self.type.value,
            'vector': self.vector.value,
            'wiki': self.wiki,
            'owner': self.owner
        }

    @property
    def alerts(self) -> list[str]:
        """The UUIDs of every alert mapped to this event."""
        return [mapping.alert.uuid for mapping in self.alert_mappings]

    @property
    def alert_versions(self) -> dict[str, str]:
        """alert uuid -> Alert.version for every alert mapped to this event, so a client that
        fetched the event can tell whether any of its alerts changed since."""
        return {mapping.alert.uuid: mapping.alert.version for mapping in self.alert_mappings}

    @property
    def alert_details(self) -> list[dict]:
        """Per-alert database state for every alert mapped to this event -- the columns that live only
        in the alerts table (never in the alert's storage directory): when it was inserted, who owns it
        and since when, and how and by whom it was dispositioned. Users are given by username. Lets a
        client reconstruct an event's timeline without loading each alert."""
        details = []
        for mapping in self.alert_mappings:
            alert = mapping.alert
            details.append({
                'uuid': alert.uuid,
                'insert_date': alert.insert_date,
                'owner': alert.owner.username if alert.owner else None,
                'owner_time': alert.owner_time,
                'disposition': alert.disposition,
                'disposition_time': alert.disposition_time,
                'disposition_user': alert.disposition_user.username if alert.disposition_user else None,
            })
        return details

    @property
    def alert_objects(self) -> list["Alert"]:
        return [m.alert for m in self.alert_mappings]

    # XXX get rid of this
    @property
    def all_observables_sorted(self) -> list[_Observable]: # XXX
        """Returns a sorted list (by type, then value) of all of the unique observables in all of the alerts in the
        event. It prefers to add observables that have FA Queue results. So if the same observable is in multiple
        alerts, but only one has FA Queue results, it will add that one to the list."""

        observables = []

        for alert in self.alert_objects:
            for observable in alert.root_analysis.all_observables:

                # Check if this observable is already in the list
                existing_observable = next((o for o in observables if o == observable), None)

                # If it is, then make sure the one that is in the list has FA Queue analysis
                if existing_observable:

                    # Continue if the version of the observable already in the list has FA Queue analysis
                    if existing_observable.faqueue_hits is not None:
                        continue

                    # If this current observable has FA Queue analysis, remove the existing observable and add the
                    # current one to the list instead
                    if observable.faqueue_hits is not None:
                        observables.remove(existing_observable)
                        observables.append(observable)

                # We haven't seen this observable yet, so just add it to the list
                else:
                    observables.append(observable)

        return sorted(observables, key=lambda o: (o.type, o.value))

    @property
    def alerts_still_analyzing(self) -> bool:
        """Returns True if any of the alerts in the event have not completed their analysis."""
        return any('Completed' not in a.status for a in self.alert_objects)

    @property
    def malware_names(self):
        names = []
        for mal in self.malware:
            names.append(mal.name)
        return names

    @property
    def company_names(self):
        names = []
        for company in self.companies:
            names.append(company.name)
        return names

    @property
    def commentf(self):
        if self.comment is None:
            return ""
        return self.comment

    @property
    def threats(self):
        threats = {}
        for mal in self.malware:
            for threat in mal.threats:
                threats[str(threat)] = True
        return threats.keys()

    @property
    def disposition(self):
        if not self.alert_mappings:
            disposition = DISPOSITION_DELIVERY
        else:
            disposition = DISPOSITION_OPEN

        for alert_mapping in self.alert_mappings:
            if alert_mapping.alert.disposition == DISPOSITION_OPEN:
                logging.warning(f"alert {alert_mapping.alert} added to event without disposition {alert_mapping.event_id}")
                continue

            try:
                if get_dispositions()[alert_mapping.alert.disposition]['rank'] > get_dispositions()[disposition]['rank']:
                    disposition = alert_mapping.alert.disposition
            except:
                pass

        return disposition

    @property
    def disposition_rank(self):
        return get_dispositions()[self.disposition]['rank']

    @property
    def sorted_tags(self) -> list[str]:
        results = get_db().query(Tag.name) \
            .join(TagMapping, Tag.id == TagMapping.tag_id) \
            .join(Alert, TagMapping.alert_id == Alert.id) \
            .join(EventMapping, Alert.id == EventMapping.alert_id) \
            .filter(EventMapping.event_id == self.id).distinct().all()

        return sorted([result[0] for result in results], key=lambda x: (-get_tag_score(x), x.lower()))

    @property
    def wiki(self) -> str:
        return ''

    @property
    def alert_with_email_and_screenshot(self) -> "Alert":
        return next((a for a in self.alert_objects if a.has_email_analysis and a.has_renderer_screenshot), None)

    @property
    def all_file_observables(self) -> list[_Observable]:
        file_observables = []

        for alert in self.alert_objects:
            for observable in alert.root_analysis.find_observables(lambda o: o.type == F_FILE):
                file_observables.append(observable)

        return file_observables

    @property
    def all_email_file_observables(self) -> list[_Observable]:
        from saq.modules.email import EmailAnalysis

        file_observables = []

        for alert in self.alert_objects:
            for observable in alert.root_analysis.find_observables(lambda o: o.type == F_FILE):
                if observable.get_analysis(EmailAnalysis):
                    file_observables.append(observable)

        return file_observables

    @property
    def all_emails(self) -> set[Analysis]:
        from saq.modules.email import EmailAnalysis

        emails = set()

        for alert in self.alert_objects:
            observables = alert.root_analysis.find_observables(lambda o: o.get_analysis(EmailAnalysis))
            email_analyses = {o.get_analysis(EmailAnalysis) for o in observables}

            # Inject the alert's UUID into the EmailAnalysis so that we maintain a link of alert->email
            for email_analysis in email_analyses:
                email_analysis.alert_uuid = alert.uuid

            emails |= email_analyses

        return emails

    @property
    def all_url_domain_counts(self) -> dict[str, int]:
        url_domain_counts = {}

        for alert in self.alert_objects:
            domain_counts = find_all_url_domains(alert.root_analysis)
            for d in domain_counts:
                if d not in url_domain_counts:
                    url_domain_counts[d] = domain_counts[d]
                else:
                    url_domain_counts[d] += domain_counts[d]

        return url_domain_counts

    @property
    def all_urls(self) -> set[str]:
        urls = set()

        for alert in self.alert_objects:
            observables = alert.root_analysis.find_observables(lambda o: o.type == F_URL)
            urls |= {o.value for o in observables}

        return urls

    @property
    def all_fqdns(self) -> set[str]:
        fqdns = set()

        for alert in self.alert_objects:
            observables = alert.root_analysis.find_observables(lambda o: o.type == F_FQDN)
            fqdns |= {o.value for o in observables}

        return fqdns

    @property
    def all_user_analysis(self) -> set[Analysis]:
        from saq.modules.user import UserAnalysis
        user_analysis = set()

        for alert in self.alert_objects:
            observables = alert.root_analysis.find_observables(lambda o: o.get_analysis(UserAnalysis))
            user_analysis |= {o.get_analysis(UserAnalysis) for o in observables}

        return user_analysis

    @property
    def showable_tags(self) -> dict[str, list]:
        special_tag_names = [tag for tag in get_config().tags if get_config().tags[tag] in ['special', 'hidden']]

        results = {}
        for alert in self.alert_objects:
            results[alert.uuid] = []
            for tag in alert.sorted_tags:
                if tag.name not in special_tag_names:
                    results[alert.uuid].append(tag)

        return results

    @property
    def tags(self) -> list:
        """Returns a list of Tag objects that are currently mapped to this event"""
        ignore_tags = [tag for tag in get_config().tags.keys() if get_config().tags[tag] in ['special', 'hidden']]
        tags = get_db().query(Tag). \
            join(EventTagMapping, Tag.id == EventTagMapping.tag_id). \
            join(Event, Event.id == EventTagMapping.event_id). \
            filter(Event.id == self.id, Tag.name.notin_(ignore_tags)). \
            order_by(Tag.name.asc()).all()

        return tags


class Lock(Base):

    __tablename__ = 'locks'
    __table_args__ = (
        Index('idx_uuid_locko_uuid', 'uuid', 'lock_uuid'),
    )

    uuid: Mapped[str] = mapped_column(
        String(36),
        primary_key=True)

    lock_uuid: Mapped[Optional[str]] = mapped_column(
        String(36),
        nullable=True,
        unique=False)

    lock_time: Mapped[datetime] = mapped_column(
        DATETIME,
        nullable=False,
        index=True)

    lock_owner: Mapped[Optional[str]] = mapped_column(
        String(512),
        nullable=True)

    node_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        index=True)

class LockedException(Exception):
    def __init__(self, target, *args, **kwargs):
        self.target = target

    def __str__(self):
        return f"LockedException: unable to get lock on {self.target} uuid {self.target.uuid}"

class Malware(Base):

    __tablename__ = 'malware'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    threats: Mapped[list["Threat"]] = relationship("Threat", passive_deletes=True, passive_updates=True)

class ThreatType(Base):

    __tablename__ = 'threat_type'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)

class Threat(Base):

    __tablename__ = 'malware_threat_mapping'

    malware_id: Mapped[int] = mapped_column(Integer, ForeignKey('malware.id', ondelete='CASCADE', onupdate='CASCADE'), primary_key=True)
    threat_type_id: Mapped[int] = mapped_column(Integer, ForeignKey('threat_type.id'), primary_key=True)
    threat_type: Mapped["ThreatType"] = relationship("ThreatType")

    def __str__(self):
        return self.threat_type.name

class ObservableMapping(Base):

    __tablename__ = 'observable_mapping'

    observable_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('observables.id', ondelete='CASCADE', onupdate='CASCADE'),
        primary_key=True)

    alert_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('alerts.id', ondelete='CASCADE', onupdate='CASCADE'),
        primary_key=True)

    alert: Mapped["Alert"] = relationship('Alert', backref='observable_mappings')
    observable: Mapped["Observable"] = relationship('Observable', backref='observable_mappings')

class ObservableRemediationMapping(Base):

    __tablename__ = 'observable_remediation_mapping'

    observable_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('observables.id', ondelete='CASCADE', onupdate='CASCADE'),
        primary_key=True)

    remediation_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('remediation.id', ondelete='CASCADE', onupdate='CASCADE'),
        primary_key=True)

    observable: Mapped["Observable"] = relationship('Observable', backref='observable_remediation_mappings')
    remediation: Mapped["Remediation"] = relationship('Remediation', backref='observable_remediation_mappings')

# this is used to automatically map tags to observables
# same as the etc/site_tags.csv really, just in the database
class ObservableTagMapping(Base):

    __tablename__ = 'observable_tag_mapping'

    tag_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('tags.id', ondelete='CASCADE', onupdate='CASCADE'),
        primary_key=True)

    observable_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('observables.id', ondelete='CASCADE', onupdate='CASCADE'),
        primary_key=True)

    observable: Mapped["Observable"] = relationship('Observable', backref='observable_tag_mapping')
    tag: Mapped["Tag"] = relationship('Tag', backref='observable_tag_mapping')


# this is used to map what observables had what tags in what alerts
# not to be confused with ObservableTagMapping (see above)
# I think this is what I had in mind when I originally created ObservableTagMapping
# but I was missing the alert_id field
# that table was later repurposed to automatically map tags to observables

class ObservableTagIndex(Base):

    __tablename__ = 'observable_tag_index'

    observable_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('observables.id', ondelete='CASCADE', onupdate='CASCADE'),
        primary_key=True)

    tag_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('tags.id', ondelete='CASCADE', onupdate='CASCADE'),
        primary_key=True)

    alert_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('alerts.id', ondelete='CASCADE', onupdate='CASCADE'),
        primary_key=True)

    observable: Mapped["Observable"] = relationship('Observable', backref='observable_tag_index')
    tag: Mapped["Tag"] = relationship('Tag', backref='observable_tag_index')
    alert: Mapped["Alert"] = relationship('Alert', backref='observable_tag_index')

class TagMapping(Base):

    __tablename__ = 'tag_mapping'

    tag_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('tags.id', ondelete='CASCADE', onupdate='CASCADE'),
        primary_key=True)

    alert_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('alerts.id', ondelete='CASCADE', onupdate='CASCADE'),
        primary_key=True)

    alert: Mapped["Alert"] = relationship('Alert', backref='tag_mapping', overlaps="tag_mappings")
    tag: Mapped["Tag"] = relationship('Tag', backref='tag_mapping')

class DetectionPoint(Base):
    """Database representation of an analysis-layer detection point, with signature
    attribution. Distinct from the analysis-layer saq.analysis.DetectionPoint;
    consumers needing both import this one as db_DetectionPoint."""

    __tablename__ = 'detection_points'
    __table_args__ = (
        UniqueConstraint('alert_id', 'content_hash', name='uq_detection_points_alert_content'),
        Index('ix_detection_points_signature', 'signature_uuid', 'signature_version'),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('alerts.id', ondelete='CASCADE', onupdate='CASCADE'),
        nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[Optional[str]] = mapped_column(MEDIUMTEXT, nullable=True)
    queue: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    signature_uuid: Mapped[str] = mapped_column(String(36), nullable=False)
    signature_version: Mapped[str] = mapped_column(String(64), nullable=False)
    # stable identity for idempotent upsert across repeated Alert.sync() calls;
    # matches DetectionPoint.content_hash in the analysis layer.
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    insert_date: Mapped[datetime] = mapped_column(
        TIMESTAMP,
        nullable=False,
        server_default=text('CURRENT_TIMESTAMP'))

    alert: Mapped["Alert"] = relationship('Alert', backref='detection_points')

class CompanyMapping(Base):

    __tablename__ = 'company_mapping'

    event_id: Mapped[int] = mapped_column(Integer, ForeignKey('events.id', ondelete='CASCADE', onupdate='CASCADE'), primary_key=True)
    company_id: Mapped[int] = mapped_column(Integer, ForeignKey('company.id', ondelete='CASCADE', onupdate='CASCADE'), primary_key=True)
    company: Mapped["Company"] = relationship("Company")

    @property
    def name(self):
        return self.company.name

class EventMapping(Base):

    __tablename__ = 'event_mapping'

    event_id: Mapped[int] = mapped_column(Integer, ForeignKey('events.id', ondelete='CASCADE', onupdate='CASCADE'), primary_key=True)
    alert_id: Mapped[int] = mapped_column(Integer, ForeignKey('alerts.id', ondelete='CASCADE', onupdate='CASCADE'), primary_key=True)

    alert: Mapped["Alert"] = relationship('Alert', backref='event_mapping')
    event: Mapped["Event"] = relationship('Event', back_populates='alert_mappings')

class EventTagMapping(Base):
    __tablename__ = 'event_tag_mapping'

    tag_id: Mapped[int] = mapped_column(
            Integer,
            ForeignKey('tags.id', ondelete='CASCADE', onupdate='CASCADE'),
            primary_key=True)

    event_id: Mapped[int] = mapped_column(
            Integer,
            ForeignKey('events.id', ondelete='CASCADE', onupdate='CASCADE'),
            primary_key=True)

    event: Mapped["Event"] = relationship('Event', backref='event_tag_mapping')
    tag: Mapped["Tag"] = relationship('Tag', backref='event_tag_mapping')



class MalwareMapping(Base):

    __tablename__ = 'malware_mapping'

    event_id: Mapped[int] = mapped_column(Integer, ForeignKey('events.id', ondelete='CASCADE', onupdate='CASCADE'), primary_key=True)
    malware_id: Mapped[int] = mapped_column(Integer, ForeignKey('malware.id', ondelete='CASCADE', onupdate='CASCADE'), primary_key=True)
    malware: Mapped["Malware"] = relationship("Malware")

    @property
    def threats(self):
        return self.malware.threats

    @property
    def name(self):
        return self.malware.name

class Message(Base):

    __tablename__ = 'messages'

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True)

    content: Mapped[str] = mapped_column(
        Text,
        nullable=False)

class MessageRouting(Base):

    __tablename__ = 'message_routing'
    __table_args__ = (
        Index('idx_message_routing_mrd', 'message_id', 'route', 'destination'),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True)

    message_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey('messages.id', ondelete='CASCADE', onupdate='CASCADE'),
        nullable=False)

    message: Mapped["Message"] = relationship('Message', foreign_keys=[message_id], backref='routing')

    route: Mapped[str] = mapped_column(
        String(64),
        nullable=False)

    destination: Mapped[str] = mapped_column(
        String(256),
        nullable=False)

    lock: Mapped[Optional[str]] = mapped_column(
        String(36),
        nullable=True)

    lock_time: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True)

class Nodes(Base):

    __tablename__ = 'nodes'
    __table_args__ = (
        Index('node_UNIQUE', 'name', unique=True, mysql_length=767),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(1024), nullable=False)
    location: Mapped[str] = mapped_column(String(1024), nullable=False)
    company_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('company.id', ondelete='CASCADE', onupdate='CASCADE'),
        nullable=False)
    last_update: Mapped[datetime] = mapped_column(DATETIME, nullable=False)
    is_primary: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text('0'))
    any_mode: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text('0'))
    status: Mapped[str] = mapped_column(
        Enum('starting', 'running', 'draining', 'drained', 'stopped', 'draining_collectors'),
        nullable=False,
        server_default=text("'stopped'"))

    # operator intent, as opposed to the observed state in status. a drain sets this to
    # offline so monitoring can tell a planned shutdown from a crash: both end up with
    # status = stopped, but only the planned one is expected to be down.
    expected_state: Mapped[str] = mapped_column(
        Enum('online', 'offline'),
        nullable=False,
        server_default=text("'online'"))

class CollectorStatus(Base):
    """Status reported by a collector service running on a node. Used by the
    node drain feature to determine when a node's collectors have flushed
    their distribution backlog."""

    __tablename__ = 'collector_status'

    node_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('nodes.id', ondelete='CASCADE', onupdate='CASCADE'),
        primary_key=True)

    # the workload_type of the collector service, e.g. 'email', 'hunter'
    name: Mapped[str] = mapped_column(String(256), primary_key=True)

    status: Mapped[str] = mapped_column(
        Enum('running', 'draining', 'drained', 'stopped'),
        nullable=False)

    # number of work_distribution rows the collector still needs to flush
    backlog_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text('0'))

    last_update: Mapped[datetime] = mapped_column(DATETIME, nullable=False)

class Observable(Base):

    __tablename__ = 'observables'
    __table_args__ = (
        UniqueConstraint('type', 'sha256', name='i_type_sha256'),
        Index('i_obs_type', 'type'),
        Index('i_obs_sha256', 'sha256'),
        Index('i_obs_value', 'value', mysql_length=767),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True)

    type: Mapped[str] = mapped_column(
        String(64),
        nullable=False)

    sha256: Mapped[bytes] = mapped_column(
        VARBINARY(32),
        nullable=False)

    value: Mapped[bytes] = mapped_column(
        BLOB,
        nullable=False)

    #
    # observable detection stuff moved to the `observable_detections` table
    #

    # DEPRECATED: detection management moved to the `observable_detections` table.
    for_detection: Mapped[bool] = mapped_column(
        BOOLEAN,
        nullable=False,
        default=False,
        server_default=text('0'))

    # DEPRECATED: detection management moved to the `observable_detections` table.
    expires_on: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True)

    # DEPRECATED: see the note on for_detection above.
    enabled_by: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey('users.id', ondelete='SET NULL'),
        nullable=True)

    # DEPRECATED: see the note on for_detection above.
    detection_context: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True)

    # DEPRECATED: see the note on for_detection above.
    batch_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        nullable=True,
        index=True)

    #
    # end deprecated columns
    #

    # an analyst annotation
    is_interesting: Mapped[bool] = mapped_column(
        BOOLEAN,
        nullable=False,
        default=False,
        server_default=text('0'))

    fa_hits: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True)

    @property
    def display_value(self):
        return self.value.decode('utf8', errors='ignore')

    tags: Mapped[list["ObservableTagIndex"]] = relationship('ObservableTagIndex', passive_deletes=True, passive_updates=True, overlaps="observable,observable_tag_index")

    @property
    def json(self):
        return {
            "id": self.id,
            "type": self.type,
            "value": base64.b64encode(self.value).decode(),
            "sha256": self.sha256.hex(),
            "is_interesting": self.is_interesting == 1,
            "fa_hits": self.fa_hits,
        }


class ObservableDetection(Base):
    """An observable that ACE should alert on.

    NOTE: There is no foreign key to ``observables``. A detection may legitimately have no corresponding
    index row (it was added ahead of ever seeing the value).

    Note the deliberate asymmetry between uniqueness and search: uniqueness is on the *binary*
    ``value_sha256``, so ``evil.com`` and ``EVIL.com`` are two distinct detections (correct -- the
    runtime redis match is case-sensitive), while ``value`` carries a case-insensitive collation so
    a single search finds both (correct for the analyst).
    """

    __tablename__ = 'observable_detections'
    __table_args__ = (
        UniqueConstraint('type', 'value_sha256', name='uq_obs_det_type_sha256'),
        Index('i_obs_det_batch_id', 'batch_id'),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True)

    type: Mapped[str] = mapped_column(
        String(64),
        nullable=False)

    value: Mapped[str] = mapped_column(
        String(MAX_DETECTION_VALUE_LENGTH, collation='utf8mb4_unicode_520_ci'),
        nullable=False)

    # Observable.sha256_bytes semantics -- NOT sha256(value) for every type. A FileObservable's
    # value is already the file's sha256 hex, so its sha256_bytes is unhex(value). Always compute
    # this through saq.database.util.observable_detection.resolve_detection_identity().
    value_sha256: Mapped[bytes] = mapped_column(
        VARBINARY(32),
        nullable=False)

    expires_on: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True)

    detection_context: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True)

    # Groups a bulk import together (see `ace_api.py --generate-batch-id`).
    batch_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        nullable=True)

    created_by: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey('users.id', ondelete='SET NULL'),
        nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP,
        nullable=False,
        server_default=text('CURRENT_TIMESTAMP'))

    modified_by: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey('users.id', ondelete='SET NULL'),
        nullable=True)

    # server_onupdate carries no DDL -- it tells the ORM the value it holds goes stale on every
    # UPDATE, so the column is expired and re-read instead of projected from the pre-UPDATE load.
    modified_at: Mapped[datetime] = mapped_column(
        TIMESTAMP,
        nullable=False,
        server_default=text('CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP'),
        server_onupdate=FetchedValue())

    created_by_user: Mapped[Optional["User"]] = relationship('User', foreign_keys=[created_by])
    modified_by_user: Mapped[Optional["User"]] = relationship('User', foreign_keys=[modified_by])

    @property
    def json(self):
        return {
            "id": self.id,
            "type": self.type,
            "value": base64.b64encode(self.value.encode("utf8")).decode(),
            "sha256": self.value_sha256.hex(),
            "expires_on": self.expires_on,
            "detection_context": self.detection_context,
            "batch_id": self.batch_id,
            "created_by": self.created_by_user.json if self.created_by_user else None,
            "created_at": self.created_at,
            "modified_by": self.modified_by_user.json if self.modified_by_user else None,
            "modified_at": self.modified_at,
        }


class PersistenceSource(Base):

    __tablename__ = 'persistence_source'

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True)

    name: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        index=True)

class Persistence(Base):

    __tablename__ = 'persistence'
    __table_args__ = (
        UniqueConstraint('source_id', 'uuid', name='idx_p_lookup'),
        Index('idx_p_cleanup', 'permanent', 'last_update'),
        Index('idx_p_clear_expired_1', 'source_id', 'permanent', 'created_at'),
        Index('idx_p_clear_expired_2', 'source_id', 'permanent', 'last_update'),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True)

    source_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('persistence_source.id', ondelete='CASCADE', onupdate='CASCADE'),
        nullable=False,
    )

    permanent: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default=text('0'))

    uuid: Mapped[str] = mapped_column(
        String(512),
        nullable=False)

    value: Mapped[Optional[bytes]] = mapped_column(
        BLOB(),
        nullable=True)

    last_update: Mapped[datetime] = mapped_column(
        TIMESTAMP,
        nullable=False,
        server_default=text('CURRENT_TIMESTAMP'))

    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP,
        nullable=False,
        server_default=text('CURRENT_TIMESTAMP'))

class Remediation(Base):

    __tablename__ = 'remediation'

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True)

    # corresponds to the observable type this remediation is for
    type: Mapped[str] = mapped_column(
        String(24),
        nullable=False)

    # corresponds to the `name` of the Remediator that initiated this remediation
    name: Mapped[str] = mapped_column(
        String(512),
        nullable=False
    )

    action: Mapped[str] = mapped_column(
        Enum('remove', 'restore'),
        nullable=False,
        default='remove',
        server_default=text("'remove'"))

    insert_date: Mapped[datetime] = mapped_column(
        TIMESTAMP,
        nullable=False,
        server_default=text('CURRENT_TIMESTAMP'))

    update_time: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP,
        nullable=True,
        server_default=None)

    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('users.id'),
        nullable=False,
        index=True)

    user: Mapped["User"] = relationship('User', backref='remediations')

    key: Mapped[str] = mapped_column(
        Text,
        nullable=False)

    # the meaning of this column diffs based on the action
    # REMOVE: the *resulting* restore key to use if you need to restore this remediation (restore_key is OUTPUT)
    # RESTORE: the restore key *value* to use if you need to restore this remediation (restore_key is INPUT)
    restore_key: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        default=None)

    result: Mapped[Optional[str]] = mapped_column(
        Enum('DELAYED', 'ERROR', 'FAILED', 'IGNORE', 'SUCCESS', 'CANCELLED'),
        nullable=True)

    comment: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True)

    @property
    def alert_uuids(self):
        """If the comment is a comma separated list of alert uuids, then that list is provided here as a property.
           Otherwise this returns an emtpy list."""
        result = []
        if self.comment is None:
            return result

        for _uuid in self.comment.split(','):
            try:
                validate_uuid(_uuid)
                result.append(_uuid)
            except ValueError:
                continue

        return result

    lock: Mapped[Optional[str]] = mapped_column(
        String(36),
        nullable=True)

    lock_time: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True)

    status: Mapped[str] = mapped_column(
        Enum('NEW', 'IN_PROGRESS', 'COMPLETED'),
        nullable=False,
        default='NEW',
        server_default=text("'NEW'"))

    @property
    def json(self):
        return {
            'id': self.id,
            'type': self.type,
            'action': self.action,
            'insert_date': self.insert_date,
            'user_id': self.user_id,
            'key': self.key,
            'result': self.result,
            'comment': self.comment,
            'successful': self.successful,
            'company_id': self.company_id,
            'status': self.status,
        }

    def __str__(self):
        return f"Remediation: {self.action} - {self.type} - {self.status} - {self.key} - {self.result}"

def get_current_remediation(remediator_name: str, observable_type: str, observable_value: str) -> Optional[Remediation]:
    """Returns the current remediation status of the given target."""
    return (
        get_db()
        .query(Remediation)
        .filter(
            Remediation.name == remediator_name,
            Remediation.type == observable_type,
            Remediation.key == observable_value
        )
        .order_by(Remediation.id.desc())
        .first()
    )

class RemediationHistory(Base):

    __tablename__ = 'remediation_history'

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True)

    remediation_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('remediation.id', ondelete='CASCADE', onupdate='CASCADE'),
        primary_key=True)

    insert_date: Mapped[datetime] = mapped_column(
        TIMESTAMP,
        nullable=False,
        server_default=text('CURRENT_TIMESTAMP'))

    result: Mapped[str] = mapped_column(
        Enum('DELAYED', 'ERROR', 'FAILED', 'IGNORE', 'SUCCESS', 'CANCELLED'),
        nullable=False)

    message: Mapped[str] = mapped_column(
        Text,
        nullable=False)

    status: Mapped[str] = mapped_column(
        Enum('NEW', 'IN_PROGRESS', 'COMPLETED'),
        nullable=False,
        default='NEW')


class FileCollection(Base):
    """Tracks file collection requests that can be retried when hosts are offline."""

    __tablename__ = 'file_collection'
    __table_args__ = (
        Index('idx_file_collection_name', 'name', mysql_length=255),
        Index('idx_file_collection_type', 'type'),
        Index('idx_file_collection_result', 'result'),
        Index('idx_file_collection_collector_loop', 'status', 'name', desc('insert_date'), mysql_length={'name': 255}),
        Index('idx_file_collection_observable_lookup', 'name', 'type', 'alert_uuid', mysql_length={'name': 255}),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True)

    # corresponds to the observable type this collection is for (e.g., file_location)
    type: Mapped[str] = mapped_column(
        String(64),
        nullable=False)

    # corresponds to the `name` of the FileCollector that will handle this collection
    name: Mapped[str] = mapped_column(
        String(512),
        nullable=False)

    # the observable value (e.g., hostname@/path/to/file)
    key: Mapped[str] = mapped_column(
        Text,
        nullable=False)

    insert_date: Mapped[datetime] = mapped_column(
        TIMESTAMP,
        nullable=False,
        index=True,
        server_default=text('CURRENT_TIMESTAMP'))

    update_time: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP,
        nullable=True,
        index=True,
        server_default=None)

    # user who requested collection (nullable for automated collections)
    user_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey('users.id', ondelete='SET NULL'),
        nullable=True)

    user: Mapped[Optional["User"]] = relationship('User', backref='file_collections')

    # link to the originating alert
    alert_uuid: Mapped[Optional[str]] = mapped_column(
        String(36),
        nullable=True,
        index=True)

    result: Mapped[Optional[str]] = mapped_column(
        Enum('DELAYED', 'ERROR', 'FAILED', 'SUCCESS', 'CANCELLED', 'HOST_OFFLINE', 'FILE_NOT_FOUND'),
        nullable=True)

    result_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True)

    lock: Mapped[Optional[str]] = mapped_column(
        String(36),
        nullable=True)

    lock_time: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True)

    status: Mapped[str] = mapped_column(
        Enum('NEW', 'IN_PROGRESS', 'COMPLETED'),
        nullable=False,
        index=True,
        default='NEW',
        server_default=text("'NEW'"))

    retry_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text('0'))

    max_retries: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=10,
        server_default=text('10'))

    # path to the collected file after successful collection
    collected_file_path: Mapped[Optional[str]] = mapped_column(
        String(1024),
        nullable=True)

    # SHA256 hash of the collected file
    collected_file_sha256: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True)

    @property
    def json(self):
        return {
            'id': self.id,
            'type': self.type,
            'name': self.name,
            'key': self.key,
            'insert_date': self.insert_date,
            'update_time': self.update_time,
            'user_id': self.user_id,
            'alert_uuid': self.alert_uuid,
            'result': self.result,
            'result_message': self.result_message,
            'status': self.status,
            'retry_count': self.retry_count,
            'max_retries': self.max_retries,
            'collected_file_path': self.collected_file_path,
            'collected_file_sha256': self.collected_file_sha256,
        }

    def __str__(self):
        return f"FileCollection: {self.name} - {self.type} - {self.status} - {self.key} - {self.result}"


class FileCollectionHistory(Base):
    """Tracks the history of file collection attempts."""

    __tablename__ = 'file_collection_history'

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True)

    file_collection_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('file_collection.id', ondelete='CASCADE', onupdate='CASCADE'),
        nullable=False)

    file_collection: Mapped["FileCollection"] = relationship('FileCollection', backref='history')

    insert_date: Mapped[datetime] = mapped_column(
        TIMESTAMP,
        nullable=False,
        index=True,
        server_default=text('CURRENT_TIMESTAMP'))

    result: Mapped[str] = mapped_column(
        Enum('DELAYED', 'ERROR', 'FAILED', 'SUCCESS', 'CANCELLED', 'HOST_OFFLINE', 'FILE_NOT_FOUND'),
        nullable=False)

    message: Mapped[str] = mapped_column(
        Text,
        nullable=False)

    status: Mapped[str] = mapped_column(
        Enum('NEW', 'IN_PROGRESS', 'COMPLETED'),
        nullable=False,
        default='NEW')


class ExternalRemediationCheck(Base):
    """Tracks recurring background polls against an external system to discover
    whether *that system* has remediated a target observable (e.g. an email
    delivery). Unlike ``Remediation``, ACE did not initiate the action — we are
    only observing it. See ``saq/remediation/external/`` for the daemon."""

    __tablename__ = 'external_remediation_check'
    __table_args__ = (
        Index('idx_erc_probe_name', 'probe_name'),
        Index('idx_erc_observable_lookup', 'probe_name', 'observable_type', 'alert_uuid',
              mysql_length={'probe_name': 64, 'observable_type': 64}),
        Index('idx_erc_collector_loop', 'status', 'probe_name', desc('insert_date'),
              mysql_length={'probe_name': 64}),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # registered name of the ExternalRemediationProbe subclass that owns this row
    probe_name: Mapped[str] = mapped_column(String(64), nullable=False)

    # observable that the probe consumes (e.g. "email_delivery")
    observable_type: Mapped[str] = mapped_column(String(64), nullable=False)
    observable_value: Mapped[str] = mapped_column(Text, nullable=False)

    # link to the originating alert (not a strict FK to keep cross-shard moves cheap)
    alert_uuid: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    status: Mapped[str] = mapped_column(
        Enum('NEW', 'IN_PROGRESS', 'COMPLETED'),
        nullable=False,
        index=True,
        default='NEW',
        server_default=text("'NEW'"))

    # NULL while still polling. Set when the row transitions to COMPLETED.
    result: Mapped[Optional[str]] = mapped_column(
        Enum('CONFIRMED', 'NOT_FOUND', 'EXPIRED', 'ERROR', 'CANCELLED', 'SUPERSEDED'),
        nullable=True)

    result_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    insert_date: Mapped[datetime] = mapped_column(
        TIMESTAMP, nullable=False, index=True,
        server_default=text('CURRENT_TIMESTAMP'))

    update_time: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP, nullable=True, index=True, server_default=None)

    retry_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text('0'))

    # Per-row caps. The probe class supplies the values; we persist them on the
    # row so an in-flight check survives a probe-config change.
    max_retries: Mapped[int] = mapped_column(Integer, nullable=False)
    deadline: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    lock: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    lock_time: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Serialized ``list[RemediationEvent]`` on CONFIRMED; the timeline aggregator
    # deserializes and renders these directly. MEDIUMTEXT (16 MB) is overkill
    # for normal payloads but cheap insurance against a probe returning a long
    # vendor history.
    events_json: Mapped[Optional[str]] = mapped_column(MEDIUMTEXT, nullable=True)

    # Opaque JSON dict frozen at queue time. Surfaced back to the probe as
    # ``ProbeTarget.context`` on every attempt, including background re-polls
    # by the daemon worker. Probes own their own context contract — the
    # persistence layer treats the payload as a passthrough.
    context_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    @property
    def json(self):
        return {
            'id': self.id,
            'probe_name': self.probe_name,
            'observable_type': self.observable_type,
            'observable_value': self.observable_value,
            'alert_uuid': self.alert_uuid,
            'status': self.status,
            'result': self.result,
            'result_message': self.result_message,
            'insert_date': self.insert_date,
            'update_time': self.update_time,
            'retry_count': self.retry_count,
            'max_retries': self.max_retries,
            'deadline': self.deadline,
            'last_error': self.last_error,
        }

    def __str__(self):
        return (f"ExternalRemediationCheck: {self.probe_name} - {self.observable_type} - "
                f"{self.status} - {self.observable_value} - {self.result}")


class Tag(Base):

    __tablename__ = 'tags'

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True)

    name: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        unique=True)

    @property
    def display(self):
        tag_name = self.name.split(':')[0]
        if tag_name in get_config().tags and get_config().tags[tag_name] == "special":
            return False
        return True

    @property
    def style(self):
        tag_name = self.name.split(':')[0]
        if tag_name in get_config().tags:
            return get_config().tag_css_class[get_config().tags[tag_name]]
        else:
            return 'label-default'

    @reconstructor
    def init_on_load(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class User(UserMixin, Base):

    __tablename__ = 'users'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False, index=True)
    password_hash: Mapped[Optional[str]] = mapped_column(String(256))
    omniscience: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=text('0'))
    timezone: Mapped[Optional[str]] = mapped_column(String(512))
    display_name: Mapped[Optional[str]] = mapped_column(String(1024))
    queue: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default=QUEUE_DEFAULT,
        server_default=text("'default'"))
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, unique=False, default=True, server_default=text('1'))

    # AuthApiKey has two FKs to users (user_id, created_by); disambiguate on user_id.
    api_keys: Mapped[list["AuthApiKey"]] = relationship(
        'AuthApiKey',
        foreign_keys='AuthApiKey.user_id',
        back_populates='user',
        passive_deletes=True,
        cascade='all, delete-orphan')

    def __str__(self):
        return self.username

    @property
    def json(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "timezone": self.timezone,
            "display_name": self.display_name,
            "default_queue": self.queue,
            "enabled": self.enabled == 1,
        }

    @property
    def gui_display(self):
        """Returns the textual representation of this user in the GUI.
           If the user has a display_name value set then that is returned.
           Otherwise, the username is returned."""

        if self.display_name is not None:
            return self.display_name

        return self.username

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')
    
    @password.setter
    def password(self, value):
        self.password_hash = hash_password(value)

    def verify_password(self, value):
        """Verify password and migrate legacy hashes to bcrypt.

        If verification succeeds and the stored hash is a legacy werkzeug format,
        the hash is automatically updated to bcrypt. The caller must commit the
        session to persist this change.
        """
        if verify_password_hash(value, self.password_hash):
            # Migrate legacy werkzeug hash to bcrypt on successful verification
            # TODO: Remove this migration block once all users are migrated
            if not self.password_hash.startswith("$2"):
                self.password_hash = hash_password(value)
                logging.info(f"migrated werkzeug hash to bcrypt for user {self.username}")
            return True
        return False

class AuthGroup(Base):

    __tablename__ = 'auth_group'

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True)

    name: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
        unique=True)

    permissions: Mapped[list["AuthGroupPermission"]] = relationship('AuthGroupPermission', passive_deletes=True, passive_updates=True, back_populates='group')

class AuthGroupUser(Base):

    __tablename__ = 'auth_group_user'

    group_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('auth_group.id', ondelete='CASCADE', onupdate='CASCADE'),
        primary_key=True)

    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('users.id', ondelete='CASCADE', onupdate='CASCADE'),
        primary_key=True)

    group: Mapped["AuthGroup"] = relationship('AuthGroup')
    user: Mapped["User"] = relationship('User')

class AuthPermissionCatalog(Base):

    __tablename__ = 'auth_permission_catalog'
    __table_args__ = (
        UniqueConstraint('major', 'minor', name='u_perm'),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True)

    major: Mapped[str] = mapped_column(
        String(512, collation='ascii_general_ci'),
        nullable=False)

    minor: Mapped[str] = mapped_column(
        String(512, collation='ascii_general_ci'),
        nullable=False)

    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True)

class AuthUserPermission(Base):

    __tablename__ = 'auth_user_permission'
    __table_args__ = (
        UniqueConstraint('user_id', 'major', 'minor', 'effect', name='u_user_perm'),
        Index('i_user_major_minor', 'user_id', 'major', 'minor'),
        Index('i_user_effect', 'user_id', 'effect'),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True)

    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('users.id', ondelete='CASCADE', onupdate='CASCADE'),
        nullable=False)

    major: Mapped[str] = mapped_column(
        String(512, collation='ascii_general_ci'),
        nullable=False)

    minor: Mapped[str] = mapped_column(
        String(512, collation='ascii_general_ci'),
        nullable=False)

    effect: Mapped[str] = mapped_column(
        Enum('ALLOW', 'DENY'),
        nullable=False,
        default='ALLOW',
        server_default=text("'ALLOW'"))

    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP,
        nullable=False,
        server_default=text('CURRENT_TIMESTAMP'))

    created_by: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey('users.id', ondelete='SET NULL', onupdate='CASCADE'),
        nullable=True)

    user: Mapped["User"] = relationship('User', foreign_keys=[user_id])
    created_by_user: Mapped[Optional["User"]] = relationship('User', foreign_keys=[created_by])

class AuthGroupPermission(Base):

    __tablename__ = 'auth_group_permission'
    __table_args__ = (
        UniqueConstraint('group_id', 'major', 'minor', 'effect', name='u_group_perm'),
        Index('i_group_major_minor', 'group_id', 'major', 'minor'),
        Index('i_group_effect', 'group_id', 'effect'),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True)

    group_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('auth_group.id', ondelete='CASCADE', onupdate='CASCADE'),
        nullable=False)

    major: Mapped[str] = mapped_column(
        String(512, collation='ascii_general_ci'),
        nullable=False)

    minor: Mapped[str] = mapped_column(
        String(512, collation='ascii_general_ci'),
        nullable=False)

    effect: Mapped[str] = mapped_column(
        Enum('ALLOW', 'DENY'),
        nullable=False,
        default='ALLOW',
        server_default=text("'ALLOW'"))

    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP,
        nullable=False,
        server_default=text('CURRENT_TIMESTAMP'))

    created_by: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey('users.id', ondelete='SET NULL', onupdate='CASCADE'),
        nullable=True)

    group: Mapped["AuthGroup"] = relationship('AuthGroup', back_populates='permissions')
    created_by_user: Mapped[Optional["User"]] = relationship('User', foreign_keys=[created_by])

class AuthApiKey(Base):

    __tablename__ = 'auth_api_key'
    __table_args__ = (
        Index('i_api_key_user', 'user_id'),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True)

    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('users.id', ondelete='CASCADE', onupdate='CASCADE'),
        nullable=False)

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False)

    # sha256 of the plaintext key -- the only stored representation. A key is revealed once at
    # creation and never again; there is no recoverable/encrypted copy.
    key_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True)

    # True: the key inherits its owner's full permissions (the pre-refactor single-key behavior).
    # False: the key is restricted to its own scope rows, intersected with the owner's permissions.
    inherit_user_scope: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text('0'))

    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP,
        nullable=False,
        server_default=text('CURRENT_TIMESTAMP'))

    created_by: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey('users.id', ondelete='SET NULL', onupdate='CASCADE'),
        nullable=True)

    user: Mapped["User"] = relationship('User', foreign_keys=[user_id], back_populates='api_keys')
    created_by_user: Mapped[Optional["User"]] = relationship('User', foreign_keys=[created_by])
    scope: Mapped[list["AuthApiKeyPermission"]] = relationship(
        'AuthApiKeyPermission', passive_deletes=True, cascade='all, delete-orphan', back_populates='api_key')

class AuthApiKeyPermission(Base):

    __tablename__ = 'auth_api_key_permission'
    __table_args__ = (
        UniqueConstraint('api_key_id', 'major', 'minor', 'effect', name='u_api_key_perm'),
        Index('i_api_key_major_minor', 'api_key_id', 'major', 'minor'),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True)

    api_key_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey('auth_api_key.id', ondelete='CASCADE', onupdate='CASCADE'),
        nullable=False)

    major: Mapped[str] = mapped_column(
        String(512, collation='ascii_general_ci'),
        nullable=False)

    minor: Mapped[str] = mapped_column(
        String(512, collation='ascii_general_ci'),
        nullable=False)

    # v1 mints ALLOW-only (a positive allowlist); the column mirrors the user/group permission
    # tables so a future per-key DENY capability needs no schema change.
    effect: Mapped[str] = mapped_column(
        Enum('ALLOW', 'DENY'),
        nullable=False,
        default='ALLOW',
        server_default=text("'ALLOW'"))

    api_key: Mapped["AuthApiKey"] = relationship('AuthApiKey', back_populates='scope')

class SavedFilter(Base):
    """One alert-management filter belonging to one analyst.

    Every filter state is a row here -- named filters, the analyst's unsaved working set,
    and an active pivot -- which is what lets the Flask session carry nothing but UUIDs
    instead of the multi-KB filter payload it used to hold in a cookie.

    Note this table is NEVER a share target. Share links are self-describing URLs (see
    saq/gui/filter_url.py), so a link keeps working after its filter is edited or deleted
    and nothing here has to outlive its owner's intent."""

    __tablename__ = 'saved_filters'
    __table_args__ = (
        UniqueConstraint('user_id', 'name', name='uq_saved_filter_user_name'),
        Index('i_saved_filter_user_kind', 'user_id', 'kind'),
        Index('i_saved_filter_user_quick', 'user_id', 'quick_filter_order'),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True)

    # the handle the session holds. Opaque on purpose: it keeps the cookie from leaking row
    # ids, and matches the String(36) business-key convention used throughout this schema.
    uuid: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        unique=True)

    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('users.id', ondelete='CASCADE', onupdate='CASCADE'),
        nullable=False)

    # named   -- an analyst's saved filter; the only kind that is listed in the GUI
    # working -- this user's unsaved edits; a per-user singleton, overwritten in place
    # temp    -- this user's active pivot or opened share link; a per-user singleton
    #
    # The scratch kinds being singletons is what bounds this table's growth: at most two
    # rows per user beyond the ones they deliberately created.
    kind: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default='named',
        server_default=text("'named'"))

    # NULL for the scratch kinds. InnoDB treats NULLs as distinct in a UNIQUE index, so any
    # number of scratch rows coexist with the per-user unique name constraint.
    name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True)

    # doubles as the banner label for temp rows ("Tag: needs_research", "Shared link")
    description: Mapped[Optional[str]] = mapped_column(
        String(1024),
        nullable=True)

    # the [{name, inverted, values}] list, JSON-serialized. No native JSON column type is
    # used anywhere in this schema -- see ExternalRemediationCheck.context_json.
    #
    # Relative date tokens ("-24h") are stored VERBATIM and resolved on every query by
    # DateRangeFilter.apply. Never normalize one to an absolute range on the way in, or a
    # saved "Last 24h" silently freezes to whenever it was saved.
    filters_json: Mapped[str] = mapped_column(
        Text,
        nullable=False)

    # NULL: not a quick filter. Otherwise the badge's position in this user's filter bar,
    # ascending. Deliberately NOT unique so a multi-row reorder has no intermediate state
    # that violates a constraint.
    quick_filter_order: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True)

    # show a dot with the number of alerts this badge would match
    quick_filter_indicator: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text('0'))

    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP,
        nullable=False,
        server_default=text('CURRENT_TIMESTAMP'))

    # see ObservableDetection.modified_at: server_onupdate is what keeps a write's response from
    # reporting the updated_at the row had *before* that same write bumped it.
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP,
        nullable=False,
        server_default=text('CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP'),
        server_onupdate=FetchedValue())

    user: Mapped["User"] = relationship('User', foreign_keys=[user_id])

# aliased(User) forces User's mapper to configure, which resolves User.api_keys -> AuthApiKey. These
# must therefore come AFTER every model User has a relationship to is defined.
Owner = aliased(User)
DispositionBy = aliased(User)
RemediatedBy = aliased(User)

class Comment(Base):

    __tablename__ = 'comments'

    comment_id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True)

    insert_date: Mapped[datetime] = mapped_column(
        TIMESTAMP,
        nullable=False,
        index=True,
        server_default=text('CURRENT_TIMESTAMP'))

    user_id: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        index=True)

    uuid: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True)

    comment: Mapped[str] = mapped_column(Text, nullable=False)

    user: Mapped["User"] = relationship(
        'User', primaryjoin='Comment.user_id == User.id',
        foreign_keys=[user_id], backref='comments')


class ObservableComment(Base):

    __tablename__ = 'observable_comments'

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True)

    insert_date: Mapped[datetime] = mapped_column(
        TIMESTAMP,
        nullable=False,
        index=True,
        server_default=text('CURRENT_TIMESTAMP'))

    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('users.id'),
        nullable=False,
        index=True)

    observable_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('observables.id', ondelete='CASCADE'),
        nullable=False,
        index=True)

    comment: Mapped[str] = mapped_column(Text, nullable=False)

    user: Mapped["User"] = relationship('User', foreign_keys=[user_id])
    observable: Mapped["Observable"] = relationship('Observable', backref='observable_comments')


class Workload(Base):

    __tablename__ = 'workload'
    __table_args__ = (
        UniqueConstraint('uuid', 'analysis_mode', name='uuid_UNIQUE'),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True)

    uuid: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True)

    node_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('nodes.id', ondelete='CASCADE', onupdate='CASCADE'),
        nullable=False,
        index=True)

    analysis_mode: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        index=True)

    insert_date: Mapped[Optional[datetime]] = mapped_column(
        DATETIME,
        nullable=True)

    company_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('company.id', ondelete='CASCADE', onupdate='CASCADE'),
        nullable=False)

    company: Mapped["Company"] = relationship('Company', foreign_keys=[company_id])

    storage_dir: Mapped[str] = mapped_column(
        String(1024),
        nullable=False)

class EncryptedPassword(Base):

    __tablename__ = 'encrypted_passwords'

    key: Mapped[str] = mapped_column(
        String(256),
        primary_key=True)

    encrypted_value: Mapped[str] = mapped_column(
        Text,
        nullable=False)


class IncomingWorkloadType(Base):

    __tablename__ = 'incoming_workload_type'

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True)

    name: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
        unique=True)


class IncomingWorkload(Base):

    __tablename__ = 'incoming_workload'

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True)

    type_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('incoming_workload_type.id', ondelete='CASCADE', onupdate='CASCADE'),
        nullable=False)

    mode: Mapped[str] = mapped_column(
        String(256),
        nullable=False)

    work: Mapped[str] = mapped_column(
        String(36),
        nullable=False)

    insert_date: Mapped[datetime] = mapped_column(
        TIMESTAMP,
        nullable=False,
        index=True,
        server_default=text('CURRENT_TIMESTAMP'))

    type: Mapped["IncomingWorkloadType"] = relationship('IncomingWorkloadType')


class NodeMode(Base):

    __tablename__ = 'node_modes'

    node_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('nodes.id', ondelete='CASCADE', onupdate='CASCADE'),
        primary_key=True)

    analysis_mode: Mapped[str] = mapped_column(
        String(256),
        primary_key=True)


class NodeModeExcluded(Base):

    __tablename__ = 'node_modes_excluded'

    node_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('nodes.id', ondelete='CASCADE', onupdate='CASCADE'),
        primary_key=True)

    analysis_mode: Mapped[str] = mapped_column(
        String(256),
        primary_key=True)


class AnalysisModePriority(Base):

    __tablename__ = 'analysis_mode_priority'

    analysis_mode: Mapped[str] = mapped_column(
        String(256),
        primary_key=True)

    priority: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text('0'))


class WorkDistributionGroup(Base):

    __tablename__ = 'work_distribution_groups'

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True)

    name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        unique=True)


class WorkDistribution(Base):

    __tablename__ = 'work_distribution'
    __table_args__ = (
        Index('fk_work_status', 'work_id', 'status'),
        Index('idx_wd_lock_uuid_status', 'lock_uuid', 'status'),
        Index('idx_wd_group_status', 'group_id', 'status'),
    )

    group_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('work_distribution_groups.id', ondelete='CASCADE', onupdate='CASCADE'),
        primary_key=True)

    work_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey('incoming_workload.id', ondelete='CASCADE', onupdate='CASCADE'),
        primary_key=True,
        index=True)

    status: Mapped[str] = mapped_column(
        Enum('READY', 'COMPLETED', 'ERROR', 'LOCKED'),
        nullable=False,
        default='READY',
        server_default=text("'READY'"))

    lock_time: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP,
        nullable=True)

    lock_uuid: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True)

    # how many times delivery of this work item has failed with a retriable error.
    attempt_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text('0'))


class SandboxSubmission(Base):
    """Tracks files submitted to sandbox providers for deduplication and quota management."""

    __tablename__ = 'sandbox_submissions'
    __table_args__ = (
        UniqueConstraint('sha256', 'sandbox_type', name='uq_sandbox_submissions_sha256_type'),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True)

    sandbox_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True)

    external_id: Mapped[Optional[str]] = mapped_column(
        String(256),
        nullable=True)

    verdict: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True)

    score: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True)

    submitted_at: Mapped[datetime] = mapped_column(
        TIMESTAMP,
        nullable=False,
        server_default=text('CURRENT_TIMESTAMP'))

    completed_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP,
        nullable=True)


class AnalysisResultCache(CacheBase):
    """Per-module analysis delta cache.

    Lives in the dedicated analysis-result-cache database (CacheBase metadata).
    The table is partitioned daily by created_at, which forces created_at into
    the primary key (MySQL requires the partitioning column in every unique
    key). the cache is append-only and reads pick the freshest non-expired row.
    """

    __tablename__ = 'analysis_result_cache'
    __table_args__ = (
        Index('idx_module_expires', 'module_name', 'expires_at'),
    )

    cache_key: Mapped[str] = mapped_column(
        String(64),
        primary_key=True)

    module_name: Mapped[str] = mapped_column(
        String(512),
        nullable=False)

    module_version: Mapped[int] = mapped_column(
        Integer,
        nullable=False)

    observable_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False)

    observable_value: Mapped[str] = mapped_column(
        Text,
        nullable=False)

    delta_zstd: Mapped[bytes] = mapped_column(
        LONGBLOB,
        nullable=False)

    delta_uncompressed_size: Mapped[int] = mapped_column(
        Integer,
        nullable=False)

    has_blob_refs: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default=text('0'))

    # part of the primary key so the table can be partitioned by it
    created_at: Mapped[datetime] = mapped_column(
        MYSQL_DATETIME(fsp=6),
        primary_key=True,
        nullable=False,
        server_default=text('CURRENT_TIMESTAMP(6)'))

    expires_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        index=True)


class BlobRef(CacheBase):
    """Explicit reference counting for blobs stored in the analysis blob store.

    Lives in the dedicated analysis-result-cache database (CacheBase metadata).
    Rows are composite-PK'd on (sha256, referrer_kind, referrer_id, created_at).
    created_at is in the key so the table can be partitioned by it. Deleting a
    referrer's row doesn't delete the underlying blob, a separate downstream
    sweep deletes blobs with zero refs.
    """

    __tablename__ = 'blob_refs'
    __table_args__ = (
        Index('idx_by_referrer', 'referrer_kind', 'referrer_id'),
    )

    sha256: Mapped[str] = mapped_column(
        String(64),
        primary_key=True)

    referrer_kind: Mapped[str] = mapped_column(
        String(32),
        primary_key=True)

    referrer_id: Mapped[str] = mapped_column(
        String(128),
        primary_key=True)

    # part of the primary key so the table can be partitioned by it
    created_at: Mapped[datetime] = mapped_column(
        MYSQL_DATETIME(fsp=6),
        primary_key=True,
        nullable=False,
        server_default=text('CURRENT_TIMESTAMP(6)'))


class BrocessConnErr(BrocessBase):
    """Failed connection counts by (source, destination, port).

    Populated by an external bro/zeek feed, not by ACE. 
    """

    __tablename__ = 'connerr'
    __table_args__ = (
        Index('idx_sourceip_destip', 'sourceip', 'destip'),
        Index('idx_sourceip', 'sourceip'),
        Index('idx_destip', 'destip'),
    )

    sourceip: Mapped[int] = mapped_column(
        MYSQL_INTEGER(unsigned=True),
        primary_key=True)

    destip: Mapped[int] = mapped_column(
        MYSQL_INTEGER(unsigned=True),
        primary_key=True)

    destport: Mapped[int] = mapped_column(
        Integer,
        primary_key=True)

    numconnections: Mapped[Optional[int]] = mapped_column(
        BigInteger,
        nullable=True)

    firstconnectdate: Mapped[Optional[float]] = mapped_column(
        DOUBLE(asdecimal=False),
        nullable=True)


class BrocessConnLog(BrocessBase):
    """Successful connection counts by (source, destination, port)."""

    __tablename__ = 'connlog'
    __table_args__ = (
        Index('idx_sourceip_destip', 'sourceip', 'destip'),
        Index('idx_sourceip', 'sourceip'),
        Index('idx_destip', 'destip'),
    )

    sourceip: Mapped[int] = mapped_column(
        MYSQL_INTEGER(unsigned=True),
        primary_key=True)

    destip: Mapped[int] = mapped_column(
        MYSQL_INTEGER(unsigned=True),
        primary_key=True)

    destport: Mapped[int] = mapped_column(
        Integer,
        primary_key=True)

    numconnections: Mapped[Optional[int]] = mapped_column(
        BigInteger,
        nullable=True)

    firstconnectdate: Mapped[Optional[float]] = mapped_column(
        DOUBLE(asdecimal=False),
        nullable=True)


class BrocessHttpLog(BrocessBase):
    """How often each http host has been seen.

    Backs the "uncommon network" heuristic in saq/crawlphish_filter.py.
    """

    __tablename__ = 'httplog'

    host: Mapped[bytes] = mapped_column(
        VARBINARY(255),
        primary_key=True)

    numconnections: Mapped[Optional[int]] = mapped_column(
        BigInteger,
        nullable=True)

    firstconnectdate: Mapped[Optional[float]] = mapped_column(
        DOUBLE(asdecimal=False),
        nullable=True)


class BrocessSmtpLog(BrocessBase):
    """How often each (sender, recipient) email conversation has been seen.

    source and destination are varbinary(255), a BYTE
    limit -- saq/modules/email/logging.py::export_to_brocess encodes to utf-8
    and truncates to 255 bytes before writing.
    """

    __tablename__ = 'smtplog'

    source: Mapped[bytes] = mapped_column(
        VARBINARY(255),
        primary_key=True)

    destination: Mapped[bytes] = mapped_column(
        VARBINARY(255),
        primary_key=True)

    numconnections: Mapped[Optional[int]] = mapped_column(
        BigInteger,
        nullable=True)

    firstconnectdate: Mapped[Optional[float]] = mapped_column(
        DOUBLE(asdecimal=False),
        nullable=True)


class EmailThreadMessage(BrocessBase):
    """Per-message metadata used to reconstruct email conversations (threads).

    Identifiers such as message-id / thread-id have no hard length limit
    (RFC 5322), so they are stored full-length as TEXT and indexed via
    fixed-width BINARY(32) SHA-256 hash columns (UNHEX(SHA2(value, 256))).
    """

    __tablename__ = 'email_thread_message'
    __table_args__ = (
        UniqueConstraint('thread_id_hash', 'message_id_hash', name='uniq_thread_message'),
        Index('idx_thread_date', 'thread_id_hash', 'message_date'),
        Index('idx_subject', 'normalized_subject_hash'),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True)

    insert_date: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text('CURRENT_TIMESTAMP'))

    thread_id: Mapped[str] = mapped_column(
        Text,
        nullable=False)

    thread_id_hash: Mapped[bytes] = mapped_column(
        BINARY(32),
        nullable=False)

    message_id: Mapped[str] = mapped_column(
        Text,
        nullable=False)

    message_id_hash: Mapped[bytes] = mapped_column(
        BINARY(32),
        nullable=False)

    in_reply_to: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True)

    normalized_subject: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True)

    normalized_subject_hash: Mapped[Optional[bytes]] = mapped_column(
        BINARY(32),
        nullable=True)

    from_address: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True)

    from_domain: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True)

    direction: Mapped[Optional[int]] = mapped_column(
        TINYINT(),
        nullable=True)

    message_date: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True)


class EmailThreadDomain(BrocessBase):
    """Participant domains seen in each thread.

    Used as the "established in-thread domains" that a newly-arriving sender
    domain is compared against for look-a-like detection. entry_hash keeps the
    per-thread uniqueness key fixed-width so domain/address can stay
    arbitrary-length TEXT.

    Rows are per-MESSAGE: entry_hash covers (message_id, domain, address, role).
    """

    __tablename__ = 'email_thread_domain'
    __table_args__ = (
        UniqueConstraint('thread_id_hash', 'entry_hash', name='uniq_thread_domain'),
        Index('idx_thread', 'thread_id_hash'),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True)

    thread_id: Mapped[str] = mapped_column(
        Text,
        nullable=False)

    thread_id_hash: Mapped[bytes] = mapped_column(
        BINARY(32),
        nullable=False)

    message_id_hash: Mapped[Optional[bytes]] = mapped_column(
        BINARY(32),
        nullable=True)

    domain: Mapped[str] = mapped_column(
        Text,
        nullable=False)

    address: Mapped[str] = mapped_column(
        Text,
        nullable=False)

    role: Mapped[str] = mapped_column(
        String(16),
        nullable=False)

    entry_hash: Mapped[bytes] = mapped_column(
        BINARY(32),
        nullable=False)

    # deprecated. it counted repeat sightings back when a row was per-thread;
    # with per-message rows it stays 1. count messages with
    # COUNT(DISTINCT message_id_hash) instead.
    numseen: Mapped[Optional[int]] = mapped_column(
        BigInteger,
        nullable=True,
        server_default=text('1'))

    firstseendate: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True)


class EmailArchive(EmailArchiveBase):
    """One row per archived email, keyed by (server_id, SHA-256 hash)."""

    __tablename__ = 'archive'
    __table_args__ = (
        UniqueConstraint('server_id', 'hash', 'insert_date', name='idx_server_id'),
        Index('idx_insert_date', 'insert_date'),
    )

    archive_id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True)

    server_id: Mapped[int] = mapped_column(
        Integer,
        nullable=False)

    hash: Mapped[bytes] = mapped_column(
        BINARY(32),
        nullable=False)

    insert_date: Mapped[datetime] = mapped_column(
        DateTime,
        primary_key=True,
        nullable=False,
        server_default=text('CURRENT_TIMESTAMP'))


class EmailArchiveIndex(EmailArchiveBase):
    """Fast-search index over archived emails: (field, hashed value) -> archive_id."""

    __tablename__ = 'archive_index'
    __table_args__ = (
        PrimaryKeyConstraint('hash', 'archive_id', 'field', 'insert_date'),
        Index('idx_archive_id', 'archive_id'),
        Index('idx_field_hash', 'field', 'hash'),
    )

    field: Mapped[str] = mapped_column(
        MYSQL_ENUM('env_from', 'env_to', 'body_from', 'body_to', 'subject',
                   'decoded_subject', 'message_id', 'content', 'url'),
        nullable=False)

    hash: Mapped[bytes] = mapped_column(
        BINARY(32),
        nullable=False)

    archive_id: Mapped[int] = mapped_column(
        Integer,
        nullable=False)

    insert_date: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text('CURRENT_TIMESTAMP'))


class EmailHistory(EmailArchiveBase):
    """Per-(message-id, recipient) delivery history.

    message_id / recipient have no hard length limit so they are stored
    full-length as TEXT and indexed via fixed-width BINARY(32) SHA-256 hash
    columns (UNHEX(SHA2(value, 256))).
    """

    __tablename__ = 'email_history'
    __table_args__ = (
        UniqueConstraint('message_id_hash', 'recipient_hash', 'insert_date',
                         name='idx_eh_message_id_recipient'),
        Index('idx_eh_insert_date', 'insert_date'),
        Index('idx_eh_message_id', 'message_id_hash'),
        Index('idx_eh_recipient', 'recipient_hash'),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True)

    insert_date: Mapped[datetime] = mapped_column(
        DateTime,
        primary_key=True,
        nullable=False,
        server_default=text('CURRENT_TIMESTAMP'))

    message_id: Mapped[str] = mapped_column(
        Text,
        nullable=False)

    message_id_hash: Mapped[bytes] = mapped_column(
        BINARY(32),
        nullable=False)

    recipient: Mapped[str] = mapped_column(
        Text,
        nullable=False)

    recipient_hash: Mapped[bytes] = mapped_column(
        BINARY(32),
        nullable=False)


class EmailArchiveServer(EmailArchiveBase):
    """Registry of hosts that own archived emails. Not partitioned."""

    __tablename__ = 'archive_server'
    __table_args__ = (
        UniqueConstraint('hostname', name='idx_hostname'),
    )

    server_id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True)

    hostname: Mapped[str] = mapped_column(
        String(256),
        nullable=False)


# NOTE there is no database relationship between these tables
Alert.workload = relationship('Workload', foreign_keys=[Alert.uuid], primaryjoin='Workload.uuid == Alert.uuid')
Alert.delayed_analysis = relationship('DelayedAnalysis', foreign_keys=[Alert.uuid], primaryjoin='DelayedAnalysis.uuid == Alert.uuid', overlaps="workload")
Alert.lock = relationship('Lock', foreign_keys=[Alert.uuid], primaryjoin='Lock.uuid == Alert.uuid', overlaps="delayed_analysis,workload")
Alert.nodes = relationship('Nodes', foreign_keys=[Alert.location], primaryjoin='Nodes.name == Alert.location')