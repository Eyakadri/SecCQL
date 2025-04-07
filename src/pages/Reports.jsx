import React, { useEffect, useState } from 'react';
import { fetchReports } from '../services/api';

const Reports = () => {
    const [reports, setReports] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const getReports = async () => {
            try {
                const data = await fetchReports();
                setReports(data);
            } catch (error) {
                console.error("Error fetching reports:", error);
            } finally {
                setLoading(false);
            }
        };

        getReports();
    }, []);

    if (loading) {
        return <div>Loading reports...</div>;
    }
    if (!loading && reports.length === 0) {
        return <div>No reports available or failed to fetch reports.</div>;
    }

    return (
        <div>
            <h1>Generated Reports</h1>
            {reports.length === 0 ? (
                <p>No reports available.</p>
            ) : (
                <ul>
                    {reports.map((report, index) => (
                        <li key={index}>
                            <h2>{report.title}</h2>
                            <p>{report.date}</p>
                            <a href={report.link} target="_blank" rel="noopener noreferrer">View Report</a>
                        </li>
                    ))}
                </ul>
            )}
        </div>
    );
};

export default Reports;