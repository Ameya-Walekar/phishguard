// src/api/backend.js

// This function reaches out to your FastAPI backend to grab the historical scan logs
export const fetchLogs = async () => {
  try {
    // Make sure this matches your actual FastAPI endpoint for logs
    const response = await fetch('https://phishguard-backend-yh0j.onrender.com/api/logs'); 
    
    if (!response.ok) {
      throw new Error('Network response was not ok');
    }
    
    const data = await response.json();
    const ignoredHosts = [
      "https://6a1aa732c8c2cb19786f2be9--friendly-mandazi-cc5db3.netlify.app/"
    ];

    return data.filter(log => {
      const url = log.url || log.website || "";
      return !ignoredHosts.some(host => url.includes(host));
    });
  } catch (error) {
    console.error("Failed to fetch threat logs:", error);
    
    // If the backend is off, we return dummy data so you can still build the UI!
    return [];
  }
};