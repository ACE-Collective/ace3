from app.blueprints import auth

import logging
from urllib.parse import urlparse

from flask import render_template, redirect, request, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user

from app.auth.forms import LoginForm, ChangePasswordForm, PASS_SPECIAL_CHARS, PASS_MIN_LENGTH
from app.models import User
from saq.database import get_db

def get_remote_ipv4():
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        return request.environ['REMOTE_ADDR']
    else:
        return request.environ['HTTP_X_FORWARDED_FOR']

def is_safe_redirect_url(target):
    """
    Validate that the target URL is safe for redirection: a path on this site
    (what Flask-Login sends as next) or an http(s) URL on this host.
    """
    if not target:
        return False

    # the raw target is what gets redirected to, so it must read the same here and in a browser:
    # browsers read a backslash as a slash, and drop tabs and newlines, so /<tab>//host
    # would pass the // check below and reach the browser as ///host
    if '\\' in target or any(ord(c) <= 0x20 or ord(c) == 0x7f for c in target):
        return False

    try:
        target_url = urlparse(target)
    except ValueError:
        # malformed URL (an unclosed IPv6 bracket); the caller logs the refusal
        return False

    if not target_url.scheme:
        # a path on this site; browsers read //host, ///host and so on as another host,
        # and a path relative to the login page is not something this app sends
        return target.startswith('/') and not target.startswith('//')

    # nginx passes HTTPS through uwsgi_params, so request.host_url carries the user's scheme
    ref_url = urlparse(request.host_url)
    return target_url.scheme == ref_url.scheme and target_url.netloc == ref_url.netloc

def get_safe_next_url():
    """
    Get a safe next URL for redirection, falling back to main.index if unsafe.
    """
    next_url = request.args.get('next') or request.form.get('next')
    
    if next_url and is_safe_redirect_url(next_url):
        return next_url
    
    # Log unsafe redirect attempts for security monitoring
    if next_url:
        logging.warning(f"unsafe redirect attempt blocked: {next_url} from {get_remote_ipv4()}")
    
    return url_for('main.index')

@auth.route('/login', methods=['GET', 'POST'])
def login():

    form = LoginForm()

    if not form.validate_on_submit():
        if form.is_submitted():
            # validating the form checks its CSRF token, which expires (WTF_CSRF_TIME_LIMIT)
            # or is lost with the session, so a login page left open is refused for that alone
            if 'csrf_token' in form.errors:
                logging.warning(f"login refused: form expired for {form.username.data} from {get_remote_ipv4()}: {form.errors['csrf_token']}")
                flash('The login form expired. Please sign in again.')
            else:
                flash('Invalid username or password.')

        return render_template('auth/login.html', form=form)

    try:
        user = get_db().query(User).filter_by(username=form.username.data).one_or_none()
    except Exception as e:
        logging.exception(f"login failed: invalid username {form.username.data} from {get_remote_ipv4()}: {e}")
        flash('Invalid username or password.')
        return render_template('auth/login.html', form=form)

    if user is None:
        flash('Invalid username or password.')
        return render_template('auth/login.html', form=form)

    if user.verify_password(form.password.data):
        # TODO: This is temporary and should be removed once every user is migrated to bcrypt
        # Commit any changes made by verify_password (e.g., password hash migration)
        get_db().commit()

        if not user.enabled:
            flash('User is disabled.')
            return render_template('auth/login.html', form=form)

        login_user(user, form.remember_me.data)
        
        if 'current_storage_dir' in session:
            del session['current_storage_dir']

        logging.info(f"user {user.username} logged in from {get_remote_ipv4()}")

        # Get safe next URL using validation
        next_url = get_safe_next_url()
        response = redirect(next_url)
        # remember the username so we can autofill the field
        response.set_cookie('username', user.username)
        return response

    flash('Invalid username or password.')
    logging.warning(f"login failed: invalid password for {form.username.data} from {get_remote_ipv4()}")
    return render_template('auth/login.html', form=form)


@auth.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    if 'cid' in session:
        del session['cid']

    flash('You have been logged out.')
    return redirect(url_for('main.index'))


@auth.route('/login/change', methods=['GET', 'POST'])
@login_required
def change_password():
    """Allow a user to change their own password.

    Although validations appear to be missing from this function, most validations
    are being handled by the form validators in forms.py:
        - New pass and confirm pass fields matching
        - Length requirements
        - Character complexity requirements
    """

    form = ChangePasswordForm()

    template_kwargs = {
        'form': form,
        'special': PASS_SPECIAL_CHARS,
        'min_length': PASS_MIN_LENGTH,
    }

    if form.validate_on_submit():
        user = get_db().query(User).filter_by(username=current_user.username).first()

        if not user.verify_password(form.current_password.data):
            logging.warning(
                f"user failed to provide correct existing password during password reset: {current_user.username}"
            )
            flash("Current password is incorrect", 'error')
            return render_template('auth/change-password.html', **template_kwargs)

        # user.password has a property setter decorator that handles hashing of the password upon
        # setting the password value
        user.password = form.new_password.data

        try:
            get_db().add(user)
            get_db().commit()
        except Exception as e:
            logging.error(f"error when updating user password in database: {e.__class__} - {e}")
            flash("Error when updating password. Please contact the administrator.", 'error')
            return render_template('auth/change-password.html', **template_kwargs)
        else:
            logging.info(f"user {current_user.username} successfully changed password")
            flash('Password changed successfully. Please login with new password.', 'success')
            # Invalidate session from old password and force a login.
            # (auth.logout is POST-only -- a GET redirect can no longer log anyone out.)
            logout_user()
            if 'cid' in session:
                del session['cid']
            return redirect(url_for('auth.login'))

    return render_template('auth/change-password.html', **template_kwargs)
