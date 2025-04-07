# Penetration Testing GUI

This project is a web-based penetration testing tool that allows users to configure scans, view results, and generate reports. It integrates with a Python backend to perform various security assessments.

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

## Setup Instructions

1. **Clone the repository:**
   ```
   git clone <repository-url>
   cd penetration-testing-gui
   ```

2. **Install dependencies:**
   ```
   npm install
   ```

3. **Run the application:**
   ```
   npm run dev
   ```

4. **Open your browser and navigate to:**
   ```
   http://localhost:3000
   ```

## Usage

- **Scan Configuration:** Use the Scan Configuration form to set up your penetration tests, selecting the desired scan types and parameters.
- **View Results:** After running a scan, navigate to the Scans page to view the results, including any vulnerabilities found.
- **Generate Reports:** Use the Report Generator to create reports based on the scan results, with options for different formats.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.