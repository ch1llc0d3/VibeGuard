/**
 * VibeGuard Design Token System
 * 
 * This file defines the design tokens for the three status levels:
 * - Danger (🔴)
 * - Warning (🟡)
 * - Secure (🟢)
 * 
 * These tokens ensure consistent visual representation throughout the application.
 */

const vibeTokens = {
  // Color system
  colors: {
    // Primary status colors
    danger: {
      base: '#FF3B30',
      light: '#FFD1CF',
      dark: '#CC2F26',
      contrast: '#FFFFFF',
    },
    warning: {
      base: '#FFCC00',
      light: '#FFF0B3',
      dark: '#CC9900',
      contrast: '#000000',
    },
    secure: {
      base: '#34C759',
      light: '#D1F0DB',
      dark: '#248A3D',
      contrast: '#FFFFFF',
    },
    
    // UI colors
    background: {
      primary: '#FFFFFF',
      secondary: '#F2F2F7',
      tertiary: '#E5E5EA',
    },
    text: {
      primary: '#000000',
      secondary: '#3C3C43',
      tertiary: '#8E8E93',
    },
  },
  
  // Typography
  typography: {
    fontFamily: {
      primary: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    },
    fontSize: {
      small: '0.875rem',   // 14px
      base: '1rem',        // 16px
      medium: '1.125rem',  // 18px
      large: '1.5rem',     // 24px
      xlarge: '2rem',      // 32px
    },
    fontWeight: {
      regular: 400,
      medium: 500,
      bold: 700,
    },
  },
  
  // Animation
  animation: {
    duration: {
      fast: '100ms',
      normal: '200ms',
      slow: '400ms',
    },
    easing: {
      easeOut: 'cubic-bezier(0.0, 0.0, 0.2, 1)',
      easeIn: 'cubic-bezier(0.4, 0.0, 1, 1)',
      standard: 'cubic-bezier(0.4, 0.0, 0.2, 1)',
    },
  },
  
  // Status components
  statusBadge: {
    danger: {
      backgroundColor: 'colors.danger.base',
      color: 'colors.danger.contrast',
      borderColor: 'colors.danger.dark',
      icon: '🔴',
    },
    warning: {
      backgroundColor: 'colors.warning.base',
      color: 'colors.warning.contrast',
      borderColor: 'colors.warning.dark',
      icon: '🟡',
    },
    secure: {
      backgroundColor: 'colors.secure.base',
      color: 'colors.secure.contrast',
      borderColor: 'colors.secure.dark',
      icon: '🟢',
    },
  },
  
  // Spacing
  spacing: {
    xs: '0.25rem',    // 4px
    sm: '0.5rem',     // 8px
    md: '1rem',       // 16px
    lg: '1.5rem',     // 24px
    xl: '2rem',       // 32px
    xxl: '3rem',      // 48px
  },
  
  // Border radius
  borderRadius: {
    small: '0.25rem',   // 4px
    medium: '0.5rem',   // 8px
    large: '1rem',      // 16px
    full: '9999px',
  },
};

export default vibeTokens;