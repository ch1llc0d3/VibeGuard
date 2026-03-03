import React from 'react';

export default function Footer() {
  return (
    <footer className="bg-white">
      <div className="max-w-7xl mx-auto py-12 px-4 overflow-hidden sm:px-6 lg:px-8">
        <p className="text-center text-base text-gray-400">
          &copy; {new Date().getFullYear()} VibeGuard Security. All rights reserved.
        </p>
        <p className="text-center text-sm text-gray-500 mt-1">
          Developed by the 8-Ops Squad
        </p>
      </div>
    </footer>
  );
}