import React, { useState, useEffect } from 'react';
import ScanConfigurationForm from '../components/ScanConfigurationForm';
import ScanResults from '../components/ScanResults';
import { initiateScan, fetchScanResults } from '../services/api';

const Scans = () => {
    const [scanResults, setScanResults] = useState(null);
    const [loading, setLoading] = useState(false);

    const handleScanSubmit = async (scanConfig) => {
        setLoading(true);
        const result = await initiateScan(scanConfig);
        setScanResults(result);
        setLoading(false);
    };

    useEffect(() => {
        const getResults = async () => {
            const results = await fetchScanResults();
            setScanResults(results);
        };

        getResults();
    }, []);

    return (
        <div>
            <h1>Penetration Test Scans</h1>
            <ScanConfigurationForm onSubmit={handleScanSubmit} />
            <button onClick={() => fetchScanResults().then(setScanResults)}>Refresh Results</button>
            {loading && <p>Loading scan results...</p>}
            {scanResults && <ScanResults results={scanResults} />}
        </div>
    );
};

export default Scans;