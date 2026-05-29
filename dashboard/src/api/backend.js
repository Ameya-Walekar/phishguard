// src/api/backend.js

// This function reaches out to your FastAPI backend to grab the historical scan logs
export const fetchLogs = async () => {
  try {
    // Make sure this matches your actual FastAPI endpoint for logs
    const response = await fetch('https://phishguard-backend-yh0j.onrender.com'); 
    
    if (!response.ok) {
      throw new Error('Network response was not ok');
    }
    
    const data = await response.json();
    return data;
  } catch (error) {
    console.error("Failed to fetch threat logs:", error);
    
    // If the backend is off, we return dummy data so you can still build the UI!
    return [];
  }
};