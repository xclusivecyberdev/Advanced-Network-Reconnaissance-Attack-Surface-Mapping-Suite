"""Flask web application for reconnaissance dashboard."""

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json
import os

from ..core.config import Config
from ..core.engine import ReconSuite


def create_app(config=None):
    """Create and configure Flask app."""
    app = Flask(__name__)

    # Configuration
    if config is None:
        config = Config()

    app.config['SECRET_KEY'] = config.get('flask.secret_key')
    app.config['DEBUG'] = config.get('flask.debug', False)

    # Initialize extensions
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    # Simple user model (in production, use database)
    class User(UserMixin):
        def __init__(self, id, username, password_hash):
            self.id = id
            self.username = username
            self.password_hash = password_hash

    # Demo users (in production, use database)
    users = {
        'admin': User(1, 'admin', generate_password_hash('changeme'))
    }

    @login_manager.user_loader
    def load_user(user_id):
        for user in users.values():
            if user.id == int(user_id):
                return user
        return None

    # Routes
    @app.route('/')
    @login_required
    def index():
        """Dashboard home page."""
        return render_template('index.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """Login page."""
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')

            user = users.get(username)
            if user and check_password_hash(user.password_hash, password):
                login_user(user)
                return redirect(url_for('index'))
            else:
                flash('Invalid username or password', 'error')

        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        """Logout user."""
        logout_user()
        return redirect(url_for('login'))

    @app.route('/scan', methods=['GET', 'POST'])
    @login_required
    def scan():
        """Scan page."""
        if request.method == 'POST':
            target = request.form.get('target')
            scan_type = request.form.get('scan_type', 'standard')

            # Start scan (in production, use background task)
            try:
                scanner = ReconSuite(target, scan_type, config)
                results = scanner.run(parallel=True)

                # Store results in session (in production, use database)
                scan_id = datetime.now().strftime('%Y%m%d%H%M%S')
                session[f'scan_{scan_id}'] = results.to_dict()

                flash(f'Scan completed for {target}', 'success')
                return redirect(url_for('results', scan_id=scan_id))

            except Exception as e:
                flash(f'Scan failed: {str(e)}', 'error')

        return render_template('scan.html')

    @app.route('/results/<scan_id>')
    @login_required
    def results(scan_id):
        """Show scan results."""
        scan_data = session.get(f'scan_{scan_id}')

        if not scan_data:
            flash('Scan not found', 'error')
            return redirect(url_for('scan'))

        return render_template('results.html', scan_data=scan_data, scan_id=scan_id)

    @app.route('/api/scan', methods=['POST'])
    @login_required
    def api_scan():
        """API endpoint for scanning."""
        data = request.get_json()
        target = data.get('target')
        scan_type = data.get('scan_type', 'standard')

        if not target:
            return jsonify({'error': 'Target is required'}), 400

        try:
            scanner = ReconSuite(target, scan_type, config)
            results = scanner.run(parallel=True)

            return jsonify({
                'success': True,
                'results': results.to_dict()
            })

        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @app.route('/api/export/<scan_id>/<format>')
    @login_required
    def api_export(scan_id, format):
        """API endpoint for exporting scan results."""
        scan_data = session.get(f'scan_{scan_id}')

        if not scan_data:
            return jsonify({'error': 'Scan not found'}), 404

        # Create temporary scan result object
        from ..core.scanner_base import ScanResult
        result = ScanResult(scan_data['target'], scan_data['scan_type'])
        result.__dict__.update(scan_data)

        # Generate report
        from ..reporting.report_generator import ReportGenerator
        generator = ReportGenerator(config)

        try:
            output_file = f'reports/scan_{scan_id}.{format}'
            generator.generate(result, format, output_file)

            return jsonify({
                'success': True,
                'file': output_file
            })

        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    return app


def run_app():
    """Run Flask application."""
    config = Config()
    app = create_app(config)

    host = config.get('flask.host', '127.0.0.1')
    port = config.get('flask.port', 5000)
    debug = config.get('flask.debug', False)

    print(f"\n🌐 Starting web dashboard on http://{host}:{port}")
    print(f"📝 Default credentials: admin / changeme")
    print(f"⚠️  Change the default password after first login!\n")

    app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    run_app()
