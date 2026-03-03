import React from 'react';
import Head from 'next/head';
import VibeFeed from '../components/VibeFeed';
import SecurityOverview from '../components/SecurityOverview';
import Navbar from '../components/Navbar';
import Footer from '../components/Footer';

export default function Home() {
  return (
    <div className="min-h-screen bg-gray-50">
      <Head>
        <title>VibeGuard Sentinel</title>
        <meta name="description" content="Real-time security dashboard" />
        <link rel="icon" href="/favicon.ico" />
      </Head>

      <Navbar />
      
      <main className="container mx-auto px-4 py-8">
        <h1 className="text-3xl font-bold mb-8 text-gray-800">VibeGuard Security Dashboard</h1>
        
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          <SecurityOverview />
        </div>
        
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-xl font-semibold mb-4">Real-time Vibe Feed</h2>
          <VibeFeed />
        </div>
      </main>
      
      <Footer />
    </div>
  );
}