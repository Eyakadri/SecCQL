import React, { useState } from 'react';

const ScanConfigurationForm = () => {
    const [scanType, setScanType] = useState('basic');
    const [scanDepth, setScanDepth] = useState(3);
    const [scanDelay, setScanDelay] = useState(1);
    const [proxy, setProxy] = useState('');
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');

    const handleSubmit = (e) => {
        e.preventDefault();
        if (scanDepth < 1 || scanDelay < 0) {
            alert("Please enter valid values for scan depth and delay.");
            return;
        }
        const scanConfig = {
            scanType,
            scanDepth,
            scanDelay,
            proxy,
            username,
            password,
        };
        // Call API to start the scan with scanConfig
        console.log('Starting scan with configuration:', scanConfig);
    };

    return (
        <form onSubmit={handleSubmit}>
            <h2>Scan Configuration</h2>
            <div>
                <label>Scan Type:</label>
                <select value={scanType} onChange={(e) => setScanType(e.target.value)}>
                    <option value="basic">Basic</option>
                    <option value="advanced">Advanced</option>
                </select>
            </div>
            <div>
                <label>Scan Depth:</label>
                <input
                    type="number"
                    value={scanDepth}
                    onChange={(e) => setScanDepth(e.target.value)}
                    min="1"
                />
            </div>
            <div>
                <label>Delay Between Requests (seconds):</label>
                <input
                    type="number"
                    value={scanDelay}
                    onChange={(e) => setScanDelay(e.target.value)}
                    min="0"
                />
            </div>
            <div>
                <label>Proxy:</label>
                <input
                    type="text"
                    value={proxy}
                    onChange={(e) => setProxy(e.target.value)}
                />
            </div>
            <div>
                <label>Username:</label>
                <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                />
            </div>
            <div>
                <label>Password:</label>
                <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                />
            </div>
            <button type="submit">Start Scan</button>
        </form>
    );
};

export default ScanConfigurationForm;