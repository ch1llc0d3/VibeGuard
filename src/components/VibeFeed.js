import React, { useState, useEffect } from 'react';
import { formatDistanceToNow } from 'date-fns';

const statusMap = {
  danger: { icon: '🔴', label: 'Danger', bgColor: 'bg-red-100', textColor: 'text-red-800', borderColor: 'border-red-400' },
  warning: { icon: '🟡', label: 'Warning', bgColor: 'bg-yellow-100', textColor: 'text-yellow-800', borderColor: 'border-yellow-400' },
  secure: { icon: '🟢', label: 'Secure', bgColor: 'bg-green-100', textColor: 'text-green-800', borderColor: 'border-green-400' }
};

export default function VibeFeed() {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // In a real app, this would fetch from an API
    // For now, we'll simulate data
    const fetchData = async () => {
      try {
        // This would be a real API call
        // const response = await fetch('/api/security-events');
        // const data = await response.json();
        
        // Simulated data
        const mockData = [
          {
            id: 1,
            timestamp: new Date(Date.now() - 1000 * 60 * 5),
            status: 'secure',
            message: 'System scan completed. No vulnerabilities detected.',
            source: 'System Scanner'
          },
          {
            id: 2,
            timestamp: new Date(Date.now() - 1000 * 60 * 25),
            status: 'warning',
            message: 'Suspicious login attempt detected. IP blocked after failed attempts.',
            source: 'Access Control'
          },
          {
            id: 3,
            timestamp: new Date(Date.now() - 1000 * 60 * 45),
            status: 'danger',
            message: 'Critical update required for dependency: react-router@5.1.2',
            source: 'Dependency Checker'
          },
          {
            id: 4,
            timestamp: new Date(Date.now() - 1000 * 60 * 65),
            status: 'secure',
            message: 'Firewall rules updated successfully',
            source: 'Network Security'
          },
          {
            id: 5,
            timestamp: new Date(Date.now() - 1000 * 60 * 125),
            status: 'warning',
            message: 'High CPU usage detected on API server. Investigating.',
            source: 'Performance Monitor'
          }
        ];
        
        setEvents(mockData);
        setLoading(false);
      } catch (error) {
        console.error('Error fetching security events:', error);
        setLoading(false);
      }
    };

    fetchData();
    
    // Set up a polling interval to refresh data
    const intervalId = setInterval(fetchData, 30000);
    
    return () => clearInterval(intervalId);
  }, []);

  if (loading) {
    return <div className="text-center py-8">Loading vibe feed...</div>;
  }

  return (
    <div className="overflow-hidden">
      <div className="flow-root">
        <ul className="-mb-8">
          {events.map((event, eventIdx) => {
            const status = statusMap[event.status];
            return (
              <li key={event.id}>
                <div className="relative pb-8">
                  {eventIdx !== events.length - 1 ? (
                    <span className="absolute top-5 left-5 -ml-px h-full w-0.5 bg-gray-200" aria-hidden="true" />
                  ) : null}
                  <div className="relative flex items-start space-x-3">
                    <div className={`relative px-1 ${status.bgColor} ${status.textColor} rounded-full flex h-10 w-10 items-center justify-center ring-8 ring-white`}>
                      <span className="text-xl">{status.icon}</span>
                    </div>
                    <div className="min-w-0 flex-1 py-1.5">
                      <div className="text-sm text-gray-500">
                        <div className="flex items-center space-x-2">
                          <span className={`font-medium ${status.textColor}`}>
                            {status.label}
                          </span>
                          <span className="font-medium text-gray-900">
                            {event.source}
                          </span>
                          <span className="whitespace-nowrap text-sm text-gray-500">
                            {formatDistanceToNow(event.timestamp, { addSuffix: true })}
                          </span>
                        </div>
                        <p className="mt-0.5 text-sm text-gray-700">
                          {event.message}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}