import axios from 'axios';

const API_BASE_URL = 'http://localhost:5000'; // Adjust the base URL as needed

const axiosInstance = axios.create({
    baseURL: API_BASE_URL,
    timeout: 10000, // 10 seconds timeout
});

export const initiateScan = async (scanConfig) => {
    try {
        const response = await axiosInstance.post(`/api/scan`, scanConfig);
        return response.data;
    } catch (error) {
        console.error('Error initiating scan:', error);
        throw error;
    }
};

export const getScanResults = async (scanId) => {
    try {
        const response = await axiosInstance.get(`/api/scan/${scanId}`);
        return response.data;
    } catch (error) {
        console.error('Error fetching scan results:', error);
        throw error;
    }
};

export const generateReport = async (scanId, reportFormat) => {
    try {
        const response = await axiosInstance.post(`/api/report`, { scanId, reportFormat });
        return response.data;
    } catch (error) {
        console.error('Error generating report:', error);
        throw error;
    }
};