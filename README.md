# OpenSpecimen Participant Automation Framework

This repository contains the automated API testing framework for creating participants in OpenSpecimen. It supports reading test cases from Google Sheets or CSV files, performs deep field validation, and generates a detailed HTML test report.

## 1. Clone the Repository
Clone the framework to your local machine:
```bash
git clone git@github.com:rohitrc01/Pytest_Framework.git
cd Pytest_Framework
```

## 2. Setup the Environment
Create a virtual environment and install the required dependencies:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## ⚙️ 3. Configure Credentials
1. Copy the provided sample environment file:
   ```bash
   cp .env.example .env
   ```
2. Open the new `.env` file and securely add the role passwords/usernames.

## 4. Run the Tests
Execute the test script to run all test cases and generate the built-in HTML report:
```bash
pytest main.py -v 
```

*Results will be saved in `report.html` and a timestamped CSV file (e.g., `output_results_YYYYMMDD.csv`).*
