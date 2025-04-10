import axios from 'axios';

const API_BASE_URL = 'http://localhost:5000';

const axiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
});

// Request interceptor (e.g., add auth token)
axiosInstance.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('authToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor (e.g., handle 401 errors)
axiosInstance.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      window.location.href = '/login'; // Redirect if unauthorized
    }
    return Promise.reject(error);
  }
);

// Scan APIs
export const initiateScan = async (scanConfig) => {
  try {
    const response = await axiosInstance.post('/api/scan', scanConfig);
    return response.data;
  } catch (error) {
    throw new Error(`Scan initiation failed: ${error.response?.data?.message || error.message}`);
  }
};

// Report APIs
export const generateReport = async (scanId, reportFormat = 'pdf') => {
  try {
    const response = await axiosInstance.post('/api/report', { scanId, reportFormat });
    return response.data;
  } catch (error) {
    throw new Error(`Report generation failed: ${error.response?.data?.message || error.message}`);
  }
};

// Fetch APIs
export const getScanResults = async (scanId) => {
  try {
    const response = await axiosInstance.get(`/api/scan/${scanId}`);
    return response.data;
  } catch (error) {
    throw new Error(`Failed to fetch results: ${error.response?.data?.message || error.message}`);
  }
};

export const fetchReports = async () => {
  try {
    const response = await axiosInstance.get('/api/reports');
    return response.data;
  } catch (error) {
    throw new Error(`Failed to fetch reports: ${error.response?.data?.message || error.message}`);
  }
};

export const fetchScanResults = async () => {
  try {
    const response = await axiosInstance.get('/api/scan/results');
    return response.data;
  } catch (error) {
    throw new Error(`Failed to refresh results: ${error.response?.data?.message || error.message}`);
  }
};

// Pause Scan API
export const pauseScan = async (scanId) => {
  try {
    const response = await axiosInstance.post(`/api/scan/${scanId}/pause`);
    return response.data;
  } catch (error) {
    throw new Error(`Failed to pause scan: ${error.response?.data?.message || error.message}`);
  }
};

// Resume Scan API
export const resumeScan = async (scanId) => {
  try {
    const response = await axiosInstance.post(`/api/scan/${scanId}/resume`);
    return response.data;
  } catch (error) {
    throw new Error(`Failed to resume scan: ${error.response?.data?.message || error.message}`);
  }
};

// Delete Scan API
export const deleteScan = async (scanId) => {
  try {
    const response = await axiosInstance.delete(`/api/scan/${scanId}`);
    return response.data;
  } catch (error) {
    throw new Error(`Failed to delete scan: ${error.response?.data?.message || error.message}`);
  }
};