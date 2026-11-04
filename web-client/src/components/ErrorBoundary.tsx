import { Component } from 'react';
import type { ReactNode } from 'react';

interface Props {
  fallback: ReactNode;
  children: ReactNode;
}

interface State {
  failed: boolean;
}

/**
 * What a peer sends is validated before it reaches state (protocol/inbound.ts). This is the net under
 * that: a failure while drawing shows the fallback in place of a blank page. main.tsx keeps React from
 * logging it, since the error can quote what it failed on.
 */
class ErrorBoundary extends Component<Props, State> {
  state: State = { failed: false };

  static getDerivedStateFromError(): State {
    return { failed: true };
  }

  componentDidUpdate(previous: Props): void {
    // A recovery swaps the fallback's owner's state: try drawing again when the content changes.
    if (this.state.failed && previous.children !== this.props.children) this.setState({ failed: false });
  }

  render(): ReactNode {
    return this.state.failed ? this.props.fallback : this.props.children;
  }
}

export default ErrorBoundary;
