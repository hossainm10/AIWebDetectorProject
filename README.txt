# AI Detector for Websites

A tool that scans websites for vulnerabilities using machine learning and browser automation. It combines Scikit-Learn for intelligent detection and Selenium for real-time web interaction — catching issues that static scanners tend to miss.

---

## Features

- Automated website vulnerability scanning
- ML-powered detection using Scikit-Learn
- Real browser simulation via Selenium
- Clean, readable results output

---

## Installation

Make sure to use the requirements.txt file
Make sure you have **Python 3.8+** installed, then follow these steps:

**1. Clone the repo**
```bash
git clone https://github.com/your-username/ai-detector.git
cd ai-detector
```

**2. Create a virtual environment (recommended)**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Set up WebDriver**

Selenium needs a browser driver. Download the one that matches your browser:
- [ChromeDriver](https://chromedriver.chromium.org/downloads) for Chrome
- [GeckoDriver](https://github.com/mozilla/geckodriver/releases) for Firefox

Place the driver in your system `PATH` or in the project root.

---

## Usage

Run the scanner by pointing it at a target URL:

```bash
python main.py --url https://example.com
```

**Common options:**

```bash
# Save results to a file
python main.py --url https://example.com --output results.json

# Run in headless mode (no browser window)
python main.py --url https://example.com --headless

Results will be printed to the console and saved to the output file if specified.






