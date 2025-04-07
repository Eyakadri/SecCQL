import React from 'react';

const ScanResults = ({ results }) => {
    return (
        <div className="scan-results">
            <h2>Scan Results</h2>
            {results.length === 0 ? (
                <p>No vulnerabilities found.</p>
            ) : (
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
            )}
        </div>
    );
};

export default ScanResults;