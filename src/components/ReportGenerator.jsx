import React, { useState, useEffect } from 'react';
import { generateReport, fetchScanResults } from '../services/api';

const ReportGenerator = () => {
    const [reportFormat, setReportFormat] = useState('PDF');
    const [isGenerating, setIsGenerating] = useState(false);
    const [error, setError] = useState(null);
    const [successMessage, setSuccessMessage] = useState('');
    const [scans, setScans] = useState([]);
    const [selectedScanId, setSelectedScanId] = useState('');

    useEffect(() => {
        const fetchScans = async () => {
            try {
                const results = await fetchScanResults();
                setScans(results);
                if (results.length > 0) setSelectedScanId(results[0].id);
            } catch (err) {
                setError('Failed to fetch scans.');
            }
        };
        fetchScans();
    }, []);

    const handleFormatChange = (e) => {
        setReportFormat(e.target.value);
    };

    const handleGenerateReport = async () => {
        if (!selectedScanId) {
            setError('Please select a scan.');
            return;
        }
        setIsGenerating(true);
        setError(null);
        setSuccessMessage('');

        try {
            const response = await generateReport(selectedScanId, reportFormat);
            setSuccessMessage('Report generated successfully!');
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
                <label htmlFor="scan-id">Select Scan:</label>
                <select
                    id="scan-id"
                    value={selectedScanId}
                    onChange={(e) => setSelectedScanId(e.target.value)}
                >
                    {scans.map((scan) => (
                        <option key={scan.id} value={scan.id}>
                            {scan.name || `Scan ${scan.id}`}
                        </option>
                    ))}
                </select>
            </div>
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