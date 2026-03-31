import os
import subprocess
import logging
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get allowed jails from environment variable
ALLOWED_JAILS = [jail.strip() for jail in os.getenv('ALLOWED_JAILS', 'sshd').split(',')]

def unban_ip_from_all_jails(ip_address):
    """Unban IP from all configured fail2ban jails"""
    results = []
    success_count = 0
    
    for jail in ALLOWED_JAILS:
        try:
            cmd = ['fail2ban-client', 'set', jail, 'unbanip', ip_address]
            logger.info(f"Running command: {' '.join(cmd)}")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                logger.info(f"Successfully unbanned {ip_address} from {jail}")
                results.append(f"✓ {jail}: unbanned")
                success_count += 1
            else:
                stderr_lower = result.stderr.lower()
                if "not found" in stderr_lower or "does not exist" in stderr_lower:
                    logger.info(f"IP {ip_address} was not banned in {jail}")
                    results.append(f"○ {jail}: not banned")
                else:
                    logger.error(f"Failed to unban {ip_address} from {jail}: {result.stderr}")
                    results.append(f"✗ {jail}: failed - {result.stderr.strip()}")
                    
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout unbanning {ip_address} from {jail}")
            results.append(f"✗ {jail}: timeout")
        except Exception as e:
            logger.error(f"Error unbanning {ip_address} from {jail}: {str(e)}")
            results.append(f"✗ {jail}: error - {str(e)}")
    
    return success_count > 0, results

@app.route('/')
def index():
    """Render the main page"""
    return render_template('index.html', allowed_jails_count=len(ALLOWED_JAILS))

@app.route('/unban', methods=['POST'])
def handle_unban():
    """Handle unban request"""
    try:
        data = request.get_json()
        ip_address = data.get('ip', '').strip()
        
        if not ip_address:
            return jsonify({'success': False, 'message': 'IP address is required'}), 400
        
        parts = ip_address.split('.')
        if len(parts) != 4:
            return jsonify({'success': False, 'message': 'Invalid IP address format'}), 400
        
        for part in parts:
            if not part.isdigit() or int(part) < 0 or int(part) > 255:
                return jsonify({'success': False, 'message': 'Invalid IP address format'}), 400
        
        success, results = unban_ip_from_all_jails(ip_address)
        
        if success:
            return jsonify({
                'success': True,
                'message': f'IP {ip_address} processed successfully',
                'details': results
            })
        else:
            return jsonify({
                'success': False,
                'message': f'Failed to unban IP {ip_address}',
                'details': results
            }), 500
            
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/jails', methods=['GET'])
def get_jails():
    """Return list of configured jails"""
    return jsonify({
        'jails': ALLOWED_JAILS,
        'count': len(ALLOWED_JAILS)
    })

@app.route('/health')
def health():
    """Health check endpoint"""
    try:
        cmd = ['fail2ban-client', 'status']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        fail2ban_status = 'healthy' if result.returncode == 0 else 'degraded'
    except Exception as e:
        fail2ban_status = f'unhealthy: {str(e)}'
    
    return jsonify({
        'status': 'healthy',
        'fail2ban': fail2ban_status,
        'jails_configured': len(ALLOWED_JAILS)
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)