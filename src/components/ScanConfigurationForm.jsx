import React, { useState } from 'react';

const ScanConfigurationForm = ({ onSubmit }) => {
    const [scanType, setScanType] = useState('basic');
    const [scanDepth, setScanDepth] = useState(3);
    const [scanDelay, setScanDelay] = useState(1);
    const [proxy, setProxy] = useState('');
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');

    const validateProxy = (proxy) => {
        const proxyRegex = /^(http|https):\/\/[^\s$.?#].[^\s]*$/;
        return proxy === '' || proxyRegex.test(proxy);
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        if (scanDepth < 1 || scanDelay < 0) {
            alert("Please enter valid values for scan depth and delay.");
            return;
        }
        if (!validateProxy(proxy)) {
            alert("Please enter a valid proxy URL.");
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
        onSubmit(scanConfig); // Call the passed onSubmit function
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
                    placeholder="http://proxy.example.com"
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