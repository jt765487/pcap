#!/usr/bin/env python3
"""
A simple Flask app that emulates an upload endpoint at /pcap.
It receives files via HTTP POST; every other file upload is delayed by 6 seconds
to simulate a timeout scenario.
"""

from flask import Flask, request
import time
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Global counter to alternate delay behavior.
upload_counter = 0


@app.route('/pcap', methods=['POST'])
def upload():
    global upload_counter
    upload_counter += 1

    file_name = request.headers.get('x-filename', 'unknown')

    # Use get_data() instead of data
    data = request.get_data()  # <<< CHANGE THIS LINE
    data_length = len(data) if data else 0

    # Log the received Content-Type for debugging
    content_type = request.headers.get('Content-Type')
    app.logger.info(f"Received Content-Type: {content_type}")

    app.logger.info("Received file '%s' (%d bytes)", file_name, data_length)

    if upload_counter % 20 == 0:
        app.logger.info("Delaying response for file '%s' to simulate timeout...", file_name)
        time.sleep(6)

    return "OK", 200


if __name__ == '__main__':
    # Run the app on all interfaces on port 8989.
    app.run(host="0.0.0.0", port=8989)
