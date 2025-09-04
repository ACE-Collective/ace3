from saq.analysis.analysis import Analysis
from saq.analysis.observable import Observable
from saq.analysis.presenter.analysis_presenter import AnalysisPresenter, register_analysis_presenter
from saq.constants import F_ASSET, AnalysisExecutionResult
from saq.modules import AnalysisModule


_ASSET_HOSTNAME = 'hostname'
_ASSET_DOMAIN = 'domain'
_ASSET_MAC = 'mac'
_ASSET_FQDN = 'fqdn'
_ASSET_OWNER = 'owner'
_ASSET_OS = 'os'

class AssetAnalysis(Analysis):
    """What is the summary of all the analysis we've been able to do on this asset?"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            _ASSET_HOSTNAME: None,
            _ASSET_DOMAIN: None,
            _ASSET_MAC: None,
            _ASSET_FQDN: None,
            _ASSET_OWNER: None,
            _ASSET_OS: None
        }
            
    @property
    def hostname(self):
        """Returns the (short) name of the asset, or None if it hasn't been determined yet."""
        return self.details[_ASSET_HOSTNAME]

    @hostname.setter
    def hostname(self, value):
        assert value is None or isinstance(value, str)
        self.details[_ASSET_HOSTNAME] = value

    @property
    def domain(self):
        """Returns the (short) domain of the asset, or None if it hasn't been determined yet."""
        return self.details[_ASSET_DOMAIN]

    @domain.setter
    def domain(self, value):
        assert value is None or isinstance(value, str)
        self.details[_ASSET_DOMAIN] = value

    @property
    def mac(self):
        """Returns the MAC address of the asset, or None if it hasn't been determined yet."""
        return self.details[_ASSET_MAC]

    @mac.setter
    def mac(self, value):
        assert value is None or isinstance(value, str)
        self.details[_ASSET_MAC] = value

    @property
    def fqdn(self):
        """Returns the FQDN of the asset, or None if it hasn't been determined yet."""
        return self.details[_ASSET_FQDN]

    @fqdn.setter
    def fqdn(self, value):
        assert value is None or isinstance(value, str)
        self.details[_ASSET_FQDN] = value

    @property
    def owner(self):
        """Returns the owner of the asset, or None if it hasn't been determined yet."""
        return self.details[_ASSET_OWNER]

    @owner.setter
    def owner(self, value):
        assert value is None or isinstance(value, str)
        self.details[_ASSET_OWNER] = value

    @property
    def os(self):
        """Returns the operating system of the asset, or None if it hasn't been determined yet."""
        return self.details[_ASSET_OS]

    @os.setter
    def os(self, value):
        assert value is None or isinstance(value, str)
        self.details[_ASSET_OS] = value
            
    @property
    def jinja_template_path(self):
        return "analysis/asset_analysis.html"

    def generate_summary(self):
        return f"Asset Analysis Summary: host {self.hostname} domain {self.domain} MAC {self.mac} fqdn {self.fqdn} owner {self.owner} os {self.os}"

class AssetAnalyzer(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return AssetAnalysis

    @property
    def valid_observable_types(self):
        return F_ASSET

    def get_hostname(self, asset):
        from saq.modules.asset.dns import DNSAnalysis
        from saq.modules.asset.netbios import NetBIOSAnalysis
        assert isinstance(asset, Observable)

        # check DNS resolution
        dns_analysis = asset.get_and_load_analysis(DNSAnalysis)
        if dns_analysis is not None and dns_analysis.dns_hostname is not None:
            return dns_analysis.dns_hostname

        # check NetBIOS query
        netbios_analysis = asset.get_and_load_analysis(NetBIOSAnalysis)
        if netbios_analysis is not None and netbios_analysis.netbios_name is not None:
            return netbios_analysis.netbios_name

        return None

    def get_domain(self, asset):
        from saq.modules.asset.netbios import NetBIOSAnalysis
        assert isinstance(asset, Observable)

        # check NetBIOS query
        netbios_analysis = asset.get_and_load_analysis(NetBIOSAnalysis)
        if netbios_analysis is not None and netbios_analysis.netbios_domain is not None:
            return netbios_analysis.netbios_domain

        return None

    def get_mac(self, asset):
        from saq.modules.asset.netbios import NetBIOSAnalysis
        assert isinstance(asset, Observable)

        # check NetBIOS query
        netbios_analysis = asset.get_and_load_analysis(NetBIOSAnalysis)
        if netbios_analysis is not None and netbios_analysis.netbios_mac is not None:
            return netbios_analysis.netbios_mac

        return None

    def get_fqdn(self, asset):
        from saq.modules.asset.dns import DNSAnalysis
        from saq.modules.asset.active_directory import ActiveDirectoryAnalysis
        assert isinstance(asset, Observable)

        # check DNS resolution
        dns_analysis = asset.get_and_load_analysis(DNSAnalysis)
        if dns_analysis is not None and dns_analysis.dns_fqdn is not None:
            return dns_analysis.dns_fqdn

        # check Active Directory
        ad_analysis = asset.get_and_load_analysis(ActiveDirectoryAnalysis)
        if ad_analysis is not None and ad_analysis.fqdn is not None:
            return ad_analysis.fqdn

        return None

    def get_owner(self, asset):
        from saq.modules.asset.active_directory import ActiveDirectoryAnalysis
        assert isinstance(asset, Observable)

        # check Active Directory
        ad_analysis = asset.get_and_load_analysis(ActiveDirectoryAnalysis)
        if ad_analysis is not None and ad_analysis.owner is not None:
            #logging.debug("owner = {0}".format(ad_analysis.owner))
            return ad_analysis.owner[0] # XXX this is kind of a hack

        return None

    def get_os(self, asset):
        from saq.modules.asset.active_directory import ActiveDirectoryAnalysis
        assert isinstance(asset, Observable)

        # check Active Directory
        ad_analysis = asset.get_and_load_analysis(ActiveDirectoryAnalysis)
        if ad_analysis is not None and ad_analysis.operating_system is not None:
            return ad_analysis.operating_system

        # TODO check qualys

        return None

    def execute_analysis(self, asset) -> AnalysisExecutionResult:
        from saq.modules.asset.dns import DNSAnalysis
        from saq.modules.asset.netbios import NetBIOSAnalysis
        from saq.modules.asset.active_directory import ActiveDirectoryAnalysis

        if self.get_engine().is_module_enabled(DNSAnalysis):
            dns_analysis = self.wait_for_analysis(asset, DNSAnalysis)
        if self.get_engine().is_module_enabled(NetBIOSAnalysis):
            netbios_analysis = self.wait_for_analysis(asset, NetBIOSAnalysis)
        if self.get_engine().is_module_enabled(ActiveDirectoryAnalysis):
            active_directory_analysis = self.wait_for_analysis(asset, ActiveDirectoryAnalysis)

        analysis = self.create_analysis(asset)
        assert isinstance(analysis, AssetAnalysis)

        # figure out these properties
        analysis.hostname = self.get_hostname(asset)
        analysis.domain = self.get_domain(asset)
        analysis.mac = self.get_mac(asset)
        analysis.fqdn = self.get_fqdn(asset)
        analysis.owner = self.get_owner(asset)
        analysis.os = self.get_os(asset)

        return AnalysisExecutionResult.COMPLETED

class AssetAnalysisPresenter(AnalysisPresenter):
    """Presenter for AssetAnalysis."""

    @property
    def template_path(self) -> str:
        return "analysis/asset_analysis.html"

register_analysis_presenter(AssetAnalysis, AssetAnalysisPresenter)