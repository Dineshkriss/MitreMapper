from flask import Flask, render_template, request, jsonify
import analyzer  # This imports your renamed analyzer.py script

# Initialize the Flask application
app = Flask(__name__, template_folder='templates')

# This global variable will hold the AI model so we only load it once.
mitre_mapper = None

def initialize_mapper():
    """Loads the heavy AI models into memory when the server starts."""
    global mitre_mapper
    if mitre_mapper is None:
        print("Initializing MITREMapper for the first time... (This may take a few minutes)")
        kb = analyzer.MITREKnowledgeBase()
        mitre_mapper = analyzer.MITREMapper(knowledge_base=kb)
        print("✅ MITREMapper is ready!")

@app.route('/')
def home():
    """This function serves your index.html page."""
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze_threat_report():
    """This function receives data from the webpage, runs the analysis, and sends back the result."""
    try:
        data = request.get_json()
        report_text = data.get('report')

        if not report_text:
            return jsonify({"error": "Report text is missing."}), 400

        print(f"\nReceived analysis request...")
        # Use the pre-loaded mapper to run the analysis
        analysis_results = mitre_mapper.analyze(report_text)
        print("Analysis complete. Sending results to the frontend.")

        # Return the results as JSON
        return jsonify({"data": analysis_results.to_dict()})

    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify({"error": "An error occurred during analysis."}), 500

if __name__ == '__main__':
    # Load the AI models once before starting the web server
    initialize_mapper()
    # Start the Flask web server
    app.run(host='0.0.0.0', port=5000, debug=True)