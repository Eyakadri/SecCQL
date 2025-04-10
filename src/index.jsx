import React from 'react';
import ReactDOM from 'react-dom/client'; // Updated import
import App from './App';
import './styles/App.css';

const root = ReactDOM.createRoot(document.getElementById('root')); // Updated to use createRoot
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);