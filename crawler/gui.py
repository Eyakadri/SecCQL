from flask import Flask, request, jsonify, send_from_directory
import os
import logging

# Update the static_folder path to the correct directory
app = Flask(__name__, static_folder="../public", static_url_path="/")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Serve the index.html for the root route
@app.route("/")
def serve_index():
    try:
        index_path = os.path.join(app.static_folder, "index.html")
        if not os.path.exists(index_path):
            logger.error(f"index.html not found in {app.static_folder}")
            return jsonify({"error": "index.html not found"}), 404
        return send_from_directory(app.static_folder, "index.html")
    except Exception as e:
        logger.error(f"Error serving index.html: {e}")
        return jsonify({"error": "Failed to load the page"}), 500

# Serve static files (e.g., JS, CSS, images)
@app.route("/<path:path>")
def serve_static_files(path):
    try:
        file_path = os.path.join(app.static_folder, path)
        if os.path.exists(file_path):
            return send_from_directory(app.static_folder, path)
        else:
            # Fallback to index.html for React Router
            return send_from_directory(app.static_folder, "index.html")
    except Exception as e:
        logger.error(f"Error serving static file {path}: {e}")
        return jsonify({"error": "Failed to load the resource"}), 500

# Fallback route for React Router
@app.errorhandler(404)
def not_found(e):
    try:
        return send_from_directory(app.static_folder, "index.html")
    except Exception as e:
        logger.error(f"Error serving fallback index.html: {e}")
        return jsonify({"error": "Failed to load the page"}), 500

# Example API endpoint
@app.route("/api/scan", methods=["POST"])
def start_scan():
    try:
        # ...existing code for starting a scan...
        return jsonify({"message": "Scan started successfully!"})
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        return jsonify({"error": "Failed to start scan"}), 500

@app.route('/crawl', methods=['POST'])
def crawl():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid input"}), 400
        # Perform crawling logic here
        return jsonify({"message": "Crawling started", "data": data})
    except Exception as e:
        logger.error(f"Error during crawling: {e}")
        return jsonify({"error": "Failed to start crawling"}), 500

if __name__ == "__main__":
    # Disable debug mode for production
    app.run(debug=False)