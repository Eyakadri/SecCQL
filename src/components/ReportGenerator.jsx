import React, { useState } from 'react';
import { generateReport } from '../services/api';

const ReportGenerator = ({ scanResults }) => {
    const [reportFormat, setReportFormat] = useState('PDF');
    const [isGenerating, setIsGenerating] = useState(false);
    const [error, setError] = useState(null);
    const [successMessage, setSuccessMessage] = useState('');

    const handleFormatChange = (e) => {
        setReportFormat(e.target.value);
    };

    const handleGenerateReport = async () => {
        setIsGenerating(true);
        setError(null);
        setSuccessMessage('');

        try {
            const response = await generateReport(scanResults, reportFormat);
            if (response.status === 200) {
                setSuccessMessage('Report generated successfully!');
            } else {
                throw new Error('Failed to generate report');
            }
        } catch (err) {
            setError(err.message);
        } finally {
            setIsGenerating(false);
        }
    };

    return (
        <div className="report-generator">
            <h2>Generate Report</h2>
            <div>
                <label htmlFor="report-format">Select Report Format:</label>
                <select id="report-format" value={reportFormat} onChange={handleFormatChange}>
                    <option value="PDF">PDF</option>
                    <option value="HTML">HTML</option>
                </select>
            </div>
            <button onClick={handleGenerateReport} disabled={isGenerating}>
                {isGenerating ? <span className="spinner"></span> : 'Generate Report'}
            </button>
            {error && <p className="error">{error}</p>}
            {successMessage && <p className="success">{successMessage}</p>}
        </div>
    );
};

export default ReportGenerator;