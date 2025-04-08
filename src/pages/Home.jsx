import React from 'react';
import { Link } from 'react-router-dom';
import './Home.css'; // Assuming you have some styles for the Home component

const Home = () => {
    return (
        <div className="home-container">
            <h1>Welcome to the SECCQL</h1>
            <p>
                This application allows you to configure and run penetration tests, view results, and generate reports.
            </p>
            <div className="home-links">
                <Link to="/scans" className="home-link">Configure Scans</Link>
                <Link to="/reports" className="home-link">View Reports</Link>
            </div>
        </div>
    );
};

export default Home;