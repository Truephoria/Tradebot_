// src/pages/_app.tsx
import '../styles/globals.css';
import { ThemeProvider as MuiThemeProvider } from '@mui/material/styles';
import { ThemeProvider } from '../components/ThemeProvider';
import muiTheme from '../theme';
import type { AppProps } from 'next/app';

export default function App({ Component, pageProps }: AppProps) {
  return (
    <MuiThemeProvider theme={muiTheme}>
      <ThemeProvider>
        <Component {...pageProps} />
      </ThemeProvider>
    </MuiThemeProvider>
  );
}