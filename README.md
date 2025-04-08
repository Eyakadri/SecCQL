# SecCQL: Penetration Testing Tool

SecCQL is a web-based penetration testing tool that allows users to configure scans, view results, and generate reports.

## Features
- **Frontend**: React-based GUI for configuring scans and viewing results.
- **Backend**: Python-based scanners for vulnerabilities like XSS, SQLi, SSRF, and more.
- **Crawler**: Selenium-based crawler for discovering endpoints and forms.
- **Reporting**: Generates detailed reports with charts and MITRE mappings.
- **AI**: Uses machine learning for payload generation and anomaly detection.

## Project Structure

```
penetration-testing-gui
├── public
│   ├── index.html          # Main HTML file for the application
│   └── favicon.ico         # Favicon for the application
├── src
│   ├── components          # React components for the application
│   │   ├── ScanConfigurationForm.jsx  # Form for configuring scans
│   │   ├── ScanResults.jsx  # Displays scan results
│   │   ├── ReportGenerator.jsx  # Generates reports from scan results
│   │   └── Navbar.jsx       # Navigation bar component
│   ├── pages               # Pages of the application
│   │   ├── Home.jsx        # Home page component
│   │   ├── Scans.jsx       # Page for scan configuration and results
│   │   └── Reports.jsx      # Page for report generation
│   ├── services            # API service for backend communication
│   │   └── api.js          # Functions for making API calls
│   ├── App.jsx             # Main application component
│   ├── index.js            # Entry point for the React application
│   └── styles              # CSS styles for the application
│       └── App.css         # Styles for the application
├── package.json            # npm configuration file
├── .gitignore              # Git ignore file
├── README.md               # Project documentation
└── vite.config.js          # Vite configuration file
```

## Setup
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd SecCQL
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   npm install
   ```

3. Run the application:
   ```bash
   npm run dev
   python main.py
   ```

## Usage
- **Configure Scans**: Use the GUI to set up penetration tests.
- **View Results**: Analyze vulnerabilities detected during scans.
- **Generate Reports**: Export results as PDF, HTML, or JSON.

## Contributing
Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.