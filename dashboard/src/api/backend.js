// src/api/backend.js

const BASE_URL = 'https://phishguard-backend-yh0j.onrender.com';

const ignoredHosts = [
  "https://6a1aa732c8c2cb19786f2be9--friendly-mandazi-cc5db3.netlify.app/"
];

// Fetches historical scan logs from the FastAPI backend
export const fetchLogs = async () => {
  try {
    const response = await fetch(`${BASE_URL}/api/logs`);

    if (!response.ok) {
      throw new Error('Network response was not ok');
    }

    const data = await response.json();

    return data.filter(log => {
      const url = log.url || log.website || "";
      return !ignoredHosts.some(host => url.includes(host));
    });
  } catch (error) {
    console.error("Failed to fetch threat logs:", error);
    return [];
  }
};

// Clears all scan logs from the FastAPI backend
export const clearLogs = async () => {
  const response = await fetch(`${BASE_URL}/api/logs`, {
    method: 'DELETE',
  });

  if (!response.ok) {
    throw new Error('Failed to clear logs on backend');
  }

  return true;
};