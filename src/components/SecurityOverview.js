import React, { useState, useEffect } from 'react';

const SecurityStat = ({ title, value, status, icon }) => {
  const statusColors = {
    danger: 'bg-red-100 text-red-800 border-red-300',
    warning: 'bg-yellow-100 text-yellow-800 border-yellow-300',
    secure: 'bg-green-100 text-green-800 border-green-300',
    neutral: 'bg-blue-100 text-blue-800 border-blue-300',
  };
  
  return (
    <div className={`rounded-lg shadow p-6 border-l-4 ${statusColors[status]}`}>
      <div className="flex items-center justify-between">
        <h3 className="font-medium text-lg">{title}</h3>
        <span className="text-2xl">{icon}</span>
      </div>
      <div className="mt-4">
        <p className="text-3xl font-bold">{value}</p>
      </div>
    </div>
  );
};

export default function SecurityOverview() {
  const [stats, setStats] = useState({
    loading: true,
    data: null
  });

  useEffect(() => {
    // In a real app, this would fetch from an API
    // Simulating API call with mock data
    const loadData = async () => {
      try {
        // Simulated API response delay
        await new Promise(resolve => setTimeout(resolve, 800));
        
        // Mock data
        const mockData = {
          systemStatus: 'warning',
          vulnerabilities: 3,
          lastScanTime: '2 hours ago',
          protectedServices: 12
        };
        
        setStats({
          loading: false,
          data: mockData
        });
      } catch (error) {
        console.error('Error loading security overview:', error);
        setStats({
          loading: false,
          data: null,
          error: 'Failed to load security data'
        });
      }
    };
    
    loadData();
  }, []);
  
  if (stats.loading) {
    return (
      <>
        {[1, 2, 3].map((i) => (
          <div key={i} className="rounded-lg shadow p-6 animate-pulse bg-gray-100">
            <div className="h-4 bg-gray-200 rounded w-2/3 mb-4"></div>
            <div className="h-8 bg-gray-200 rounded w-1/3"></div>
          </div>
        ))}
      </>
    );
  }
  
  if (stats.error || !stats.data) {
    return (
      <div className="col-span-3 rounded-lg shadow p-6 bg-red-50 text-red-800 border border-red-200">
        <p>Failed to load security overview data. Please try again later.</p>
      </div>
    );
  }
  
  const { data } = stats;
  
  // Determine overall status icon
  const statusIcon = {
    danger: '🔴',
    warning: '🟡',
    secure: '🟢'
  }[data.systemStatus];
  
  return (
    <>
      <SecurityStat 
        title="System Vibe" 
        value={data.systemStatus.charAt(0).toUpperCase() + data.systemStatus.slice(1)}
        status={data.systemStatus}
        icon={statusIcon}
      />
      
      <SecurityStat 
        title="Vulnerabilities" 
        value={data.vulnerabilities} 
        status={data.vulnerabilities > 0 ? "warning" : "secure"}
        icon="🛡️"
      />
      
      <SecurityStat 
        title="Protected Services" 
        value={data.protectedServices} 
        status="neutral"
        icon="🔒"
      />
    </>
  );
}