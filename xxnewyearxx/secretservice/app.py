from flask import Flask, jsonify, request
from lxml import etree

app = Flask(__name__)

@app.route('/process-resolutions')
def process_resolutions():
    try:
        xml_data = request.args.get("resolution")
        parser = etree.XMLParser(load_dtd=True, resolve_entities=True)
        root = etree.fromstring(xml_data, parser=parser)
        resolution = {
            "resolution_id": root.findtext("resolutionId"),
            "title": root.findtext("title"),
            "description": root.findtext("description"),
        }
        return jsonify({ "data": resolution }), 200
    except Exception:
        return jsonify({ "error": "Failed to parse resolution" }), 400

