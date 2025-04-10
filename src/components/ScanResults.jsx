import React from 'react';

const ScanResults = ({ results }) => {
    const handleDownload = () => {
        const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = 'scan_results.json';
        link.click();
        URL.revokeObjectURL(url);
    };

    return (
        <div className="scan-results">
            <h2>Scan Results</h2>
            {results.length === 0 ? (
                <p>No vulnerabilities found.</p>
            ) : (
                <>
                    <ul>
                        {results.map((result, index) => (
                            <li key={index} style={{ color: result.severity === 'High' ? 'red' : 'black' }}>
                                <h3>{result.title}</h3>
                                <p>{result.description}</p>
                                <p><strong>Severity:</strong> {result.severity}</p>
                                <p><strong>Details:</strong> {result.details}</p>
                            </li>
                        ))}
                    </ul>
                    <button onClick={handleDownload}>Download Results</button>
                </>
            )}
        </div>
    );
};

export default ScanResults;