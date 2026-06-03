from flask import Flask, render_template, request

from db import get_scan_history, save_scan_history
from scanner import ScanError, perform_assessment

app = Flask(__name__)


@app.route("/")
def index():
    """Render the cybersecurity-themed landing page."""
    return render_template("index.html")


@app.route("/about")
def about():
    """Explain application security assessment concepts for the project."""
    return render_template("about.html")


@app.route("/features")
def features():
    """Describe the scanner modules and what each check demonstrates."""
    return render_template("features.html")


@app.route("/history")
def history():
    """Show stored scans from the modular history database."""
    history_items = get_scan_history()
    return render_template("history.html", history_items=history_items)


@app.route("/contact")
def contact():
    """Placeholder contact page for the academic project."""
    return render_template(
        "placeholder.html",
        title="Contact",
        heading="Contact",
        message="Add your academic supervisor, internship mentor, or project contact details here.",
    )


@app.route("/scan", methods=["POST"])
def scan():
    """Run the safe educational assessment against an authorized target URL.

    Database storage is intentionally left as a placeholder so it can be wired
    in later without changing the scanning workflow.
    """
    raw_url = request.form.get("url", "").strip()

    if not raw_url:
        return render_template(
            "index.html",
            error_message="Please enter a valid URL before starting a scan.",
            entered_url=raw_url,
        )

    try:
        result = perform_assessment(raw_url)
        save_scan_history(result)
        return render_template("results.html", result=result)
    except ScanError as exc:
        return render_template(
            "index.html",
            error_message=str(exc),
            entered_url=raw_url,
        )


@app.errorhandler(404)
def page_not_found(_error):
    return render_template("index.html", error_message="The requested page was not found."), 404


if __name__ == "__main__":
    app.run(debug=True)
