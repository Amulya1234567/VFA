import axios from 'axios';

const BASE_URL = 'http://localhost:8080/api/v1';

export const analyzeVulnerabilities = async (trivyFile, pomFile) => {
  const formData = new FormData();
  formData.append('trivyReport', trivyFile);
  formData.append('pomFile', pomFile);
  const response = await axios.post(`${BASE_URL}/analyze`, formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  });
  return response.data;
};

export const downloadFixedPom = async (trivyFile, pomFile) => {
  const formData = new FormData();
  formData.append('trivyReport', trivyFile);
  formData.append('pomFile', pomFile);
  const response = await axios.post(`${BASE_URL}/generate-fix`, formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    responseType: 'blob'
  });
  const url = window.URL.createObjectURL(new Blob([response.data]));
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', 'pom-fixed.xml');
  document.body.appendChild(link);
  link.click();
  link.remove();
};

export const checkHealth = async () => {
  const response = await axios.get(`${BASE_URL}/health`);
  return response.data;
};
