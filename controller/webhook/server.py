import os
import logging
from flask import Flask, request, jsonify
import base64
import json

logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

def create_error_response(message: str, uid: str = "") -> dict:
    """Create a standardized error response for the admission webhook."""
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": uid,
            "allowed": False,
            "status": {"message": message}
        }
    }

def start_webhook_server():
    """Start the webhook server with SSL configuration."""
    try:
        cert_path = os.environ.get('CERT_PATH', '/etc/webhook/certs/tls.crt')
        key_path = os.environ.get('KEY_PATH', '/etc/webhook/certs/tls.key')
        
        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            logger.error("SSL certificate or key not found")
            raise FileNotFoundError("SSL certificate or key not found")
            
        app.run(
            host='0.0.0.0',
            port=8443,
            ssl_context=(cert_path, key_path),
            threaded=True
        )
    except Exception as e:
        logger.error(f"Failed to start webhook server: {str(e)}")
        raise

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for the webhook server."""
    return jsonify({"status": "healthy"}), 200

@app.route('/mutate', methods=['POST'])
def mutate():
    """Handle mutation requests for AWSTargetGroup resources."""
    # Initialize uid as empty string
    uid = ""
    try:
        request_info = request.json
        
        if not request_info:
            logger.warning("Received empty request body")
            return jsonify(create_error_response("No request body", uid))
            
        request_data = request_info.get("request")
        if not request_data:
            logger.warning("No request data in admission review")
            return jsonify(create_error_response("No request data", uid))
            
        uid = request_data.get("uid", "")
        
        # Extract the AWSTargetGroup object
        try:
            aws_tg = request_data["object"]
            operation = request_data.get("operation", "").upper()
            
            # Initialize metadata if not present
            if "metadata" not in aws_tg:
                aws_tg["metadata"] = {}
                
            # Add default labels if they don't exist
            if "labels" not in aws_tg["metadata"]:
                aws_tg["metadata"]["labels"] = {}
            
            aws_tg["metadata"]["labels"].update({
                "managed-by": "aws-targetgroup-controller",
                "created-by": "aws-targetgroup-operator"
            })
            
            # Initialize finalizers if not present
            if "finalizers" not in aws_tg["metadata"]:
                aws_tg["metadata"]["finalizers"] = []
            
            # Create the patch operations
            patch = [
                {
                    "op": "add",
                    "path": "/metadata/labels",
                    "value": aws_tg["metadata"]["labels"]
                }
            ]
            
            # Handle finalizer for CREATE and UPDATE operations
            if operation in ["CREATE", "UPDATE"]:
                # Skip adding finalizer if resource is being deleted
                if "deletionTimestamp" in aws_tg["metadata"]:
                    logger.info(f"Resource {aws_tg.get('metadata', {}).get('name', 'unknown')} is being deleted, skipping finalizer")
                else:
                    # Only add finalizer if it's not already present
                    if "aws.k8s.io/awstargetgroup-finalizer" not in aws_tg["metadata"].get("finalizers", []):
                        if not aws_tg["metadata"].get("finalizers"):
                            patch.append({
                                "op": "add",
                                "path": "/metadata/finalizers",
                                "value": ["aws.k8s.io/awstargetgroup-finalizer"]
                            })
                        else:
                            patch.append({
                                "op": "add",
                                "path": "/metadata/finalizers/-",
                                "value": "aws.k8s.io/awstargetgroup-finalizer"
                            })
            
            
            # Encode the patch
            patch_bytes = json.dumps(patch).encode()
            patch_b64 = base64.b64encode(patch_bytes).decode()
            
            # Construct the admission response
            admission_response = {
                "apiVersion": "admission.k8s.io/v1",
                "kind": "AdmissionReview",
                "response": {
                    "uid": uid,
                    "allowed": True,
                    "patchType": "JSONPatch",
                    "patch": patch_b64
                }
            }
            
            logger.info(f"Successfully processed mutation request for {aws_tg.get('metadata', {}).get('name', 'unknown')}")
            return jsonify(admission_response)
            
        except KeyError as e:
            error_msg = f"Missing required field in request: {str(e)}"
            logger.error(error_msg)
            return jsonify(create_error_response(error_msg, uid))
            
    except Exception as e:
        error_msg = f"Error processing mutation request: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return jsonify(create_error_response(error_msg, uid if 'uid' in locals() else ""))