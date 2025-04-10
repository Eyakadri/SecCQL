import React from 'react';
import { NavLink, Link } from 'react-router-dom';
import './Navbar.css'; // Assuming you have a CSS file for styling

const Navbar = () => {
    return (
        <nav className="navbar">
            <div className="navbar-brand">
                <Link to="/">Penetration Testing Tool</Link>
            </div>
            <ul className="navbar-links">
                <li>
                    <NavLink to="/scans" activeClassName="active-link">Scans</NavLink>
                </li>
                <li>
                    <NavLink to="/reports" activeClassName="active-link">Reports</NavLink>
                </li>
            </ul>
        </nav>
    );
};

export default Navbar;