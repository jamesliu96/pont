import { render, screen } from '@testing-library/react';
import App from './App';

test('renders powered by text', () => {
  render(<App />);
  const textElement = screen.getByText(/powered by/i);
  expect(textElement).toBeInTheDocument();
});
