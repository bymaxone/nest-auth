# React 19 Guidelines — @bymax-one/nest-auth

> **Audience:** AI agents and developers working on this codebase.
> **Stack:** React 19+, TypeScript, custom hooks
> **Rule:** Follow these guidelines for all React code in this project.

---

## Table of Contents

1. [React 19 Features](#1-react-19-features)
2. [Custom Hooks Architecture](#2-custom-hooks-architecture)
3. [Context Provider Pattern](#3-context-provider-pattern)
4. [State Management in Hooks](#4-state-management-in-hooks)
5. [Effect Patterns](#5-effect-patterns)
6. [TypeScript Integration](#6-typescript-integration)
7. [Error Handling](#7-error-handling)
8. [Performance](#8-performance)
9. [Testing Hooks](#9-testing-hooks)
10. [Anti-Patterns](#10-anti-patterns)
11. [Quick Reference Checklist](#quick-reference-checklist)

---

## 1. React 19 Features

This library targets **React 19+** as a peer dependency (`react ^19`). All code must leverage React 19 features and conventions. Do not write code that accommodates older React versions.

### 1.1 The `use()` Hook

React 19 introduces `use()`, a new primitive that reads resources during render. Unlike other hooks, `use()` can be called conditionally and after early returns.

```tsx
import { use } from 'react';

// Reading a promise — component suspends until resolved
function SessionLoader({ sessionPromise }: { sessionPromise: Promise<AuthSession> }) {
  const session = use(sessionPromise);
  return <div>Welcome, {session.user.name}</div>;
}

// Reading context conditionally — allowed with use()
function ConditionalAuth({ requireAuth }: { requireAuth: boolean }) {
  if (!requireAuth) {
    return <PublicContent />;
  }
  const auth = use(AuthContext);
  return <ProtectedContent user={auth.user} />;
}
```

**Rules for `use()` in this library:**

- Use `use()` to read context when conditional access is needed.
- Use `use()` to read promises passed as props from server components or parent components.
- Never create promises inside render and pass them to `use()`. Promises must originate from outside the rendering component (props, module scope, or a cache).
- `use()` integrates with Suspense boundaries. Ensure a `<Suspense>` ancestor exists when reading promises.

### 1.2 `useActionState`

Replaces the deprecated `useFormState`. Returns a tuple of `[state, submitAction, isPending]`. This is relevant when building form-based auth flows that consume our library hooks.

```tsx
import { useActionState } from 'react';

function LoginForm() {
  const { login } = useAuth();

  const [error, submitAction, isPending] = useActionState(
    async (_previousState: string | null, formData: FormData) => {
      const email = formData.get('email') as string;
      const password = formData.get('password') as string;
      try {
        await login(email, password);
        return null;
      } catch (err) {
        return err instanceof Error ? err.message : 'Login failed';
      }
    },
    null,
  );

  return (
    <form action={submitAction}>
      <input name="email" type="email" required />
      <input name="password" type="password" required />
      <button type="submit" disabled={isPending}>
        {isPending ? 'Signing in...' : 'Sign in'}
      </button>
      {error && <p role="alert">{error}</p>}
    </form>
  );
}
```

**When to reference `useActionState` in this library:**

- Documentation examples showing form integration with `useAuth()`.
- The library itself does not use `useActionState` internally. It is a consumer-side pattern.

### 1.3 `useOptimistic`

Provides instant UI feedback while async operations complete. Useful for logout flows or profile updates built on top of our hooks.

```tsx
import { useOptimistic } from 'react';

function ProfileName({ currentName }: { currentName: string }) {
  const [optimisticName, setOptimisticName] = useOptimistic(currentName);

  async function handleUpdate(formData: FormData) {
    const newName = formData.get('name') as string;
    setOptimisticName(newName); // Instant UI update
    await updateProfile(newName); // Server call
  }

  return (
    <form action={handleUpdate}>
      <span>{optimisticName}</span>
      <input name="name" />
      <button type="submit">Update</button>
    </form>
  );
}
```

### 1.4 `useFormStatus`

Reads the pending state of a parent `<form>` without prop drilling. Import from `react-dom`.

```tsx
import { useFormStatus } from 'react-dom';

function SubmitButton({ label }: { label: string }) {
  const { pending } = useFormStatus();
  return (
    <button type="submit" disabled={pending}>
      {pending ? 'Loading...' : label}
    </button>
  );
}
```

### 1.5 Context as Provider (New Syntax)

React 19 allows using the context object directly as a JSX provider. The old `Context.Provider` syntax is deprecated.

```tsx
// CORRECT — React 19
<AuthContext value={contextValue}>
  {children}
</AuthContext>

// DEPRECATED — do not use
<AuthContext.Provider value={contextValue}>
  {children}
</AuthContext.Provider>
```

**This library must use the new `<Context value={...}>` syntax in `AuthProvider.tsx`.**

### 1.6 `ref` as a Prop

React 19 passes `ref` as a regular prop to function components. `forwardRef` is no longer required.

```tsx
// CORRECT — React 19
function AuthInput({ ref, ...props }: { ref?: React.Ref<HTMLInputElement> } & InputProps) {
  return <input ref={ref} {...props} />;
}

// DEPRECATED — do not use forwardRef for new code
const AuthInput = forwardRef<HTMLInputElement, InputProps>((props, ref) => {
  return <input ref={ref} {...props} />;
});
```

**Rule:** Never use `forwardRef` in new code. If a component needs to accept a ref, declare it as a prop.

### 1.7 Ref Cleanup Functions

Ref callbacks can now return a cleanup function, similar to `useEffect`.

```tsx
<input
  ref={(node) => {
    if (node) {
      // Setup
      node.focus();
    }
    return () => {
      // Cleanup — called when component unmounts or ref changes
    };
  }}
/>
```

### 1.8 `useDeferredValue` with Initial Value

React 19 adds an optional `initialValue` parameter to `useDeferredValue`.

```tsx
const deferredQuery = useDeferredValue(searchQuery, '');
// Returns '' on first render, then defers updates to searchQuery
```

### 1.9 React Compiler Considerations

React 19 is designed to work with the React Compiler (previously React Forget). The compiler automatically memoizes components, hooks, and values at build time.

**Rules for compiler compatibility:**

- Write idiomatic React. Do not fight the compiler with manual micro-optimizations.
- Avoid mutating variables after render. The compiler assumes immutability.
- Follow the Rules of React strictly (pure render, stable hook call order).
- Do not rely on referential identity of objects created during render.
- When the compiler is enabled, manual `useMemo` and `useCallback` become less necessary (see Section 8).

### 1.10 Improved Error Handling

React 19 provides three new root-level error callbacks:

```tsx
createRoot(container, {
  onCaughtError: (error, errorInfo) => {
    // Errors caught by Error Boundaries
    reportToMonitoring(error, errorInfo);
  },
  onUncaughtError: (error, errorInfo) => {
    // Errors not caught by any Error Boundary
    reportToMonitoring(error, errorInfo);
  },
  onRecoverableError: (error, errorInfo) => {
    // Errors React recovered from automatically
    reportToMonitoring(error, errorInfo);
  },
});
```

This library does not configure root-level error handling (that is the consumer application's responsibility), but hooks must throw or propagate errors in ways that are compatible with these handlers.

---

## 2. Custom Hooks Architecture

The `@bymax-one/nest-auth/react` subpath exports four public hooks and one context provider. All follow strict architectural patterns.

### 2.1 Exported API Surface

| Export           | Type              | File                  | Purpose                                      |
|------------------|-------------------|-----------------------|----------------------------------------------|
| `AuthProvider`   | Component         | `AuthProvider.tsx`    | Context provider wrapping the app             |
| `useSession`     | Hook              | `useSession.ts`      | Session data, loading state, refresh          |
| `useAuth`        | Hook              | `useAuth.ts`         | login, logout, register, password flows       |
| `useAuthStatus`  | Hook              | `useAuthStatus.ts`   | Derived booleans: isAuthenticated, isLoading  |

### 2.2 Naming Conventions

**Strict rules for all hooks in this library:**

1. **Prefix with `use`** — Every hook must start with `use` followed by a PascalCase descriptor: `useSession`, `useAuth`, `useAuthStatus`.
2. **Name describes the data, not the mechanism** — `useSession` (what it provides), not `useSessionContext` or `useSessionEffect`.
3. **Internal hooks** (not exported) must also follow the `use` prefix: `useTokenRefresh`, `useSessionPoller`.
4. **Non-hook utilities must NOT use the `use` prefix** — If a function does not call other hooks, name it as a regular function: `createAuthClient`, `parseToken`, `isTokenExpired`.

```tsx
// CORRECT — hook that calls other hooks
function useTokenRefresh(client: AuthClient): void {
  useEffect(() => { /* ... */ }, [client]);
}

// CORRECT — regular function, no hooks inside
function isTokenExpired(exp: number): boolean {
  return Date.now() >= exp * 1000;
}

// WRONG — non-hook function with use prefix
function useIsTokenExpired(exp: number): boolean {  // Does not call any hooks
  return Date.now() >= exp * 1000;
}
```

### 2.3 Return Type Conventions

Each hook must return a well-defined, typed object. Use named object properties, not tuples, for hooks that return multiple values.

```tsx
// CORRECT — named object return for multi-value hooks
function useSession(): SessionHookReturn {
  return {
    user,
    status,
    isLoading,
    refresh,
    lastValidation,
  };
}

// CORRECT — single value return when appropriate
function useAuthStatus(): AuthStatusReturn {
  return {
    isAuthenticated,
    isLoading,
  };
}

// WRONG — tuple return for library hooks (harder to extend without breaking)
function useSession(): [AuthUserClient | null, boolean] {
  return [user, isLoading];
}
```

**Why objects over tuples:** Object returns are forward-compatible. Adding a new property to the return value does not break existing destructuring. Tuples require consumers to update positional access.

### 2.4 Hook Composition and Dependency Graph

The hooks in this library form a clear dependency graph:

```
AuthProvider (holds state + context)
    |
    +-- useSession (reads context: user, status, refresh)
    |       |
    |       +-- useAuthStatus (derives from useSession)
    |
    +-- useAuth (reads context: client reference, dispatches actions)
```

**Rules:**

- `useSession` and `useAuth` read directly from `AuthContext` via `useContext` (or `use()` in React 19).
- `useAuthStatus` is a thin derivation hook that composes `useSession`. It does not access context directly.
- No hook should have hidden dependencies on global state, singletons, or module-level variables.
- Every hook must declare its dependencies explicitly through context or parameters.

```tsx
// useAuthStatus composes useSession — single source of truth
export function useAuthStatus(): AuthStatusReturn {
  const { status, isLoading } = useSession();

  return {
    isAuthenticated: status === 'authenticated',
    isLoading,
  };
}
```

### 2.5 Hook Parameters

When a hook accepts configuration, use a single options object with explicit types.

```tsx
// CORRECT — options object for extensibility
interface UseSessionOptions {
  revalidateOnFocus?: boolean;
  revalidateInterval?: number;
}

function useSession(options?: UseSessionOptions): SessionHookReturn {
  const { revalidateOnFocus = true, revalidateInterval } = options ?? {};
  // ...
}

// WRONG — positional parameters become unreadable
function useSession(revalidateOnFocus?: boolean, revalidateInterval?: number) {
  // ...
}
```

### 2.6 Context Guard Pattern

Every hook that depends on `AuthContext` must validate that it is called within `AuthProvider`. Use a helper that throws a descriptive error.

```tsx
function useAuthContext(): AuthContextValue {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error(
      'useSession/useAuth must be used within <AuthProvider>. ' +
      'Wrap your component tree with <AuthProvider client={client}>.',
    );
  }
  return context;
}

// All public hooks use this guard
export function useSession(): SessionHookReturn {
  const { user, status, isLoading, refresh, lastValidation } = useAuthContext();
  return { user, status, isLoading, refresh, lastValidation };
}
```

### 2.7 No Side Effects at Module Level

Hook files must not execute side effects when imported. No fetch calls, no subscriptions, no timers at the top level. All side effects belong inside `useEffect` or event handlers.

```tsx
// WRONG — side effect at module scope
const cachedSession = fetchSession(); // Runs on import!

export function useSession() {
  // ...
}

// CORRECT — all side effects inside useEffect
export function useSession() {
  useEffect(() => {
    // Side effect safely contained
  }, []);
}
```

---

## 3. Context Provider Pattern

### 3.1 AuthProvider Architecture

`AuthProvider` is the central state manager for the React subpath. It holds session state, manages token refresh, and provides values to all child hooks via context.

```tsx
// File: src/react/AuthProvider.tsx

import { createContext, useState, useEffect, useCallback, useMemo } from 'react';
import type { AuthClient } from '../client';
import type { AuthContextValue, AuthProviderProps, SessionStatus } from './types';

export const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({
  children,
  client,
  onSessionExpired,
  revalidateInterval = 300_000, // 5 minutes
}: AuthProviderProps) {
  const [user, setUser] = useState<AuthUserClient | null>(null);
  const [status, setStatus] = useState<SessionStatus>('loading');
  const [lastValidation, setLastValidation] = useState<number | null>(null);

  const refresh = useCallback(async () => {
    try {
      setStatus('loading');
      const session = await client.getSession();
      setUser(session.user);
      setStatus('authenticated');
      setLastValidation(Date.now());
    } catch {
      setUser(null);
      setStatus('unauthenticated');
      onSessionExpired?.();
    }
  }, [client, onSessionExpired]);

  // Initial session fetch
  useEffect(() => {
    refresh();
  }, [refresh]);

  // Periodic revalidation
  useEffect(() => {
    if (revalidateInterval <= 0) return;
    const id = setInterval(refresh, revalidateInterval);
    return () => clearInterval(id);
  }, [refresh, revalidateInterval]);

  const contextValue = useMemo<AuthContextValue>(
    () => ({
      user,
      status,
      isLoading: status === 'loading',
      refresh,
      lastValidation,
      client,
    }),
    [user, status, refresh, lastValidation, client],
  );

  // React 19: Use context directly as provider
  return (
    <AuthContext value={contextValue}>
      {children}
    </AuthContext>
  );
}
```

### 3.2 Context Value Memoization

The context value object **must** be memoized with `useMemo`. Without memoization, every render of `AuthProvider` creates a new object reference, causing all consumers to re-render even if no values changed.

```tsx
// CORRECT — memoized context value
const contextValue = useMemo<AuthContextValue>(
  () => ({ user, status, isLoading: status === 'loading', refresh, lastValidation, client }),
  [user, status, refresh, lastValidation, client],
);

// WRONG — new object every render, forces all consumers to re-render
return (
  <AuthContext value={{ user, status, isLoading: status === 'loading', refresh, lastValidation, client }}>
    {children}
  </AuthContext>
);
```

### 3.3 Context Splitting Strategy

If performance profiling reveals that consumers of `useAuth` re-render when only session data changes (and vice versa), consider splitting into two contexts:

```tsx
// SessionContext — changes when session state changes
const SessionContext = createContext<SessionContextValue | undefined>(undefined);

// AuthActionsContext — stable reference (actions don't change)
const AuthActionsContext = createContext<AuthActionsContextValue | undefined>(undefined);

export function AuthProvider({ children, client, ...props }: AuthProviderProps) {
  // ...state management...

  const sessionValue = useMemo(() => ({
    user, status, isLoading: status === 'loading', refresh, lastValidation,
  }), [user, status, refresh, lastValidation]);

  // Actions rarely change — memoize once
  const actionsValue = useMemo(() => ({
    login: client.login.bind(client),
    logout: client.logout.bind(client),
    register: client.register.bind(client),
    forgotPassword: client.forgotPassword.bind(client),
    resetPassword: client.resetPassword.bind(client),
  }), [client]);

  return (
    <AuthActionsContext value={actionsValue}>
      <SessionContext value={sessionValue}>
        {children}
      </SessionContext>
    </AuthActionsContext>
  );
}
```

**When to split:** Only if profiling shows measurable re-render overhead. Start with a single context. Premature splitting adds complexity without proven benefit.

### 3.4 Avoiding Unnecessary Re-renders

Strategies to minimize unnecessary re-renders from context:

1. **Memoize the context value** (mandatory, see 3.2).
2. **Use derived hooks for subsets of data** — `useAuthStatus` reads only `status` and `isLoading`, avoiding re-renders from `user` object changes when using object identity checks.
3. **Keep the provider close to where it is needed** — Do not wrap the entire app in `AuthProvider` if only a subtree needs auth.
4. **Use `React.memo` on expensive children** — If a child component is expensive to render and does not need auth context, wrap it in `React.memo` to skip re-renders when the provider value changes.

```tsx
// Expensive component that does not need auth data
const HeavyDashboard = React.memo(function HeavyDashboard({ data }: DashboardProps) {
  // Expensive rendering...
});
```

### 3.5 Default Context Value

Use `undefined` as the default context value. This enables the guard pattern (Section 2.6) to detect missing providers at runtime.

```tsx
// CORRECT — undefined default enables detection
const AuthContext = createContext<AuthContextValue | undefined>(undefined);

// WRONG — default object hides missing provider bugs
const AuthContext = createContext<AuthContextValue>({
  user: null,
  status: 'loading',
  // ... These defaults mask a configuration error
});
```

---

## 4. State Management in Hooks

### 4.1 Session State Machine

The session state in `AuthProvider` follows a strict state machine with three states. This is a discriminated union pattern.

```
                    +-------------+
    Initial load -> |   loading   |
                    +------+------+
                           |
              +------------+-------------+
              |                          |
              v                          v
    +---------+--------+    +------------+-----------+
    |  authenticated   |    |   unauthenticated      |
    |  (user !== null) |    |   (user === null)      |
    +--------+---------+    +------------+-----------+
             |                           |
             |   logout / token expired  |
             +---------->---------------+
             |                           |
             |   login / refresh success |
             +----------<---------------+
```

```tsx
type SessionStatus = 'loading' | 'authenticated' | 'unauthenticated';

// The status and user fields are coupled:
// - 'loading':          user may be null or stale
// - 'authenticated':    user is guaranteed non-null
// - 'unauthenticated':  user is guaranteed null
```

### 4.2 useState vs useReducer

**Use `useState` when:**

- State is a single value (the session user, a loading flag).
- State transitions are simple and do not depend on the previous state in complex ways.
- The hook is small and focused.

**Use `useReducer` when:**

- Multiple state values change together (user + status + error).
- State transitions are complex or must be atomic.
- You need to guarantee consistency across related state fields.

For `AuthProvider`, `useReducer` is recommended because session state involves multiple coupled fields:

```tsx
type SessionState = {
  user: AuthUserClient | null;
  status: SessionStatus;
  error: Error | null;
  lastValidation: number | null;
};

type SessionAction =
  | { type: 'FETCH_START' }
  | { type: 'FETCH_SUCCESS'; user: AuthUserClient; timestamp: number }
  | { type: 'FETCH_ERROR'; error: Error }
  | { type: 'LOGOUT' };

function sessionReducer(state: SessionState, action: SessionAction): SessionState {
  switch (action.type) {
    case 'FETCH_START':
      return { ...state, status: 'loading' };
    case 'FETCH_SUCCESS':
      return {
        user: action.user,
        status: 'authenticated',
        error: null,
        lastValidation: action.timestamp,
      };
    case 'FETCH_ERROR':
      return {
        user: null,
        status: 'unauthenticated',
        error: action.error,
        lastValidation: null,
      };
    case 'LOGOUT':
      return {
        user: null,
        status: 'unauthenticated',
        error: null,
        lastValidation: null,
      };
    default:
      return state;
  }
}
```

**Advantages of the reducer pattern here:**

- Impossible to set `status: 'authenticated'` with `user: null` — the reducer enforces consistency.
- All state transitions are centralized and testable in isolation.
- Action types serve as documentation for every possible state change.

### 4.3 Loading States

Every hook that exposes data fetched asynchronously must expose a loading state. Use the `status` field as the single source of truth, with `isLoading` as a derived convenience boolean.

```tsx
// In useSession return
{
  user: AuthUserClient | null;
  status: 'authenticated' | 'unauthenticated' | 'loading';
  isLoading: boolean; // Derived: status === 'loading'
}
```

**Rules:**

- `isLoading` is always `status === 'loading'`. Do not maintain a separate `isLoading` state.
- During refresh, set status to `'loading'` only if the current user is null. If the user already exists (revalidation), keep the current status to avoid flicker. Use a separate `isRefreshing` flag if needed.
- The initial render must start in `'loading'` status. Never start in `'unauthenticated'` and then flip to `'authenticated'` — this causes layout shift.

```tsx
// Avoiding flicker during revalidation
function refresh() {
  if (!state.user) {
    dispatch({ type: 'FETCH_START' }); // Show loading only on initial load
  }

  try {
    const session = await client.getSession();
    dispatch({ type: 'FETCH_SUCCESS', user: session.user, timestamp: Date.now() });
  } catch (error) {
    dispatch({ type: 'FETCH_ERROR', error: error as Error });
  }
}
```

### 4.4 Immutability

All state updates must be immutable. Never mutate state objects directly.

```tsx
// CORRECT — new object
dispatch({ type: 'FETCH_SUCCESS', user: { ...session.user }, timestamp: Date.now() });

// WRONG — mutating existing state
state.user = session.user;
state.status = 'authenticated';
```

---

## 5. Effect Patterns

### 5.1 Token Refresh Effect

The periodic token refresh in `AuthProvider` is the most critical effect in this library. It must handle cleanup, prevent race conditions, and avoid memory leaks.

```tsx
useEffect(() => {
  if (revalidateInterval <= 0) return;

  const controller = new AbortController();

  const id = setInterval(async () => {
    try {
      const session = await client.getSession({ signal: controller.signal });
      dispatch({ type: 'FETCH_SUCCESS', user: session.user, timestamp: Date.now() });
    } catch (error) {
      if (!controller.signal.aborted) {
        dispatch({ type: 'FETCH_ERROR', error: error as Error });
        onSessionExpired?.();
      }
    }
  }, revalidateInterval);

  return () => {
    controller.abort();
    clearInterval(id);
  };
}, [client, revalidateInterval, onSessionExpired]);
```

### 5.2 Cleanup Functions

Every `useEffect` that creates a subscription, timer, or async operation **must** return a cleanup function.

```tsx
// CORRECT — cleanup for timer
useEffect(() => {
  const id = setInterval(refresh, interval);
  return () => clearInterval(id);
}, [refresh, interval]);

// CORRECT — cleanup for event listener
useEffect(() => {
  function handleFocus() {
    refresh();
  }
  window.addEventListener('focus', handleFocus);
  return () => window.removeEventListener('focus', handleFocus);
}, [refresh]);

// CORRECT — cleanup for async operation
useEffect(() => {
  let cancelled = false;

  async function fetchSession() {
    try {
      const session = await client.getSession();
      if (!cancelled) {
        setUser(session.user);
      }
    } catch (error) {
      if (!cancelled) {
        setError(error as Error);
      }
    }
  }

  fetchSession();

  return () => {
    cancelled = true;
  };
}, [client]);
```

### 5.3 AbortController Pattern

For fetch-based operations, prefer `AbortController` over boolean flags. It actually cancels the network request.

```tsx
useEffect(() => {
  const controller = new AbortController();

  async function fetchSession() {
    try {
      const response = await fetch('/api/auth/session', {
        signal: controller.signal,
      });
      const data = await response.json();
      dispatch({ type: 'FETCH_SUCCESS', user: data.user, timestamp: Date.now() });
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        // Request was cancelled — do nothing
        return;
      }
      dispatch({ type: 'FETCH_ERROR', error: error as Error });
    }
  }

  fetchSession();

  return () => controller.abort();
}, []);
```

**Rules:**

- Create a new `AbortController` inside each `useEffect` call.
- Abort in the cleanup function.
- Check for `AbortError` in catch blocks and silently ignore it.
- Pass the signal to all fetch calls and any underlying `AuthClient` methods that support it.

### 5.4 Avoiding Race Conditions

When multiple effect invocations overlap (e.g., rapid prop changes), later results must not overwrite earlier ones that resolved last.

```tsx
useEffect(() => {
  let currentRequest = true;

  async function validate() {
    try {
      const session = await client.getSession();
      if (currentRequest) {
        // Only apply if this is still the latest request
        dispatch({ type: 'FETCH_SUCCESS', user: session.user, timestamp: Date.now() });
      }
    } catch (error) {
      if (currentRequest) {
        dispatch({ type: 'FETCH_ERROR', error: error as Error });
      }
    }
  }

  validate();

  return () => {
    currentRequest = false;
  };
}, [client, sessionTrigger]);
```

### 5.5 Dependency Array Rules

1. **Include all reactive values** — Every prop, state, or derived value used inside the effect must appear in the dependency array.
2. **Never lie about dependencies** — Do not omit values to "prevent re-runs." Fix the logic instead.
3. **Use `useCallback` for function dependencies** — If a function is in the dependency array, stabilize it with `useCallback`.
4. **Trust the linter** — The `react-hooks/exhaustive-deps` ESLint rule must be enabled and have zero suppressions in the codebase.

```tsx
// CORRECT — all dependencies listed
useEffect(() => {
  const id = setInterval(refresh, revalidateInterval);
  return () => clearInterval(id);
}, [refresh, revalidateInterval]); // Both used inside

// WRONG — missing dependency
useEffect(() => {
  const id = setInterval(refresh, revalidateInterval);
  return () => clearInterval(id);
}, [revalidateInterval]); // Missing 'refresh'

// WRONG — empty deps to "run once" when values are used
useEffect(() => {
  client.getSession().then(setUser);
}, []); // Missing 'client' — stale closure if client changes
```

### 5.6 Focus and Visibility Revalidation

The library should revalidate the session when the browser tab regains focus, following the stale-while-revalidate pattern.

```tsx
useEffect(() => {
  function handleVisibilityChange() {
    if (document.visibilityState === 'visible') {
      refresh();
    }
  }

  document.addEventListener('visibilitychange', handleVisibilityChange);
  return () => document.removeEventListener('visibilitychange', handleVisibilityChange);
}, [refresh]);
```

### 5.7 Effect Sequencing

Effects in `AuthProvider` run in a specific order. Document and enforce this:

1. **Initial session fetch** — runs on mount, fetches current session from server.
2. **Periodic revalidation** — sets up interval for token refresh.
3. **Focus revalidation** — listens for tab focus events.
4. **Session expiry callback** — fires `onSessionExpired` when session becomes invalid.

Each effect must be independent. Do not combine multiple concerns into a single `useEffect`.

```tsx
// CORRECT — separate effects for separate concerns
useEffect(() => { /* initial fetch */ }, [refresh]);
useEffect(() => { /* periodic revalidation */ }, [refresh, revalidateInterval]);
useEffect(() => { /* focus revalidation */ }, [refresh]);

// WRONG — one giant effect for everything
useEffect(() => {
  refresh();
  const id = setInterval(refresh, revalidateInterval);
  document.addEventListener('visibilitychange', handleVisibility);
  return () => {
    clearInterval(id);
    document.removeEventListener('visibilitychange', handleVisibility);
  };
}, [refresh, revalidateInterval]);
```

---

## 6. TypeScript Integration

### 6.1 Typing Hook Return Values

Every hook must have an explicitly defined return type interface. Do not rely on type inference for public API surfaces.

```tsx
// types.ts
export interface SessionHookReturn {
  user: AuthUserClient | null;
  status: SessionStatus;
  isLoading: boolean;
  refresh: () => Promise<void>;
  lastValidation: number | null;
}

export interface AuthHookReturn {
  login: (email: string, password: string, options?: LoginOptions) => Promise<AuthClientResponse>;
  register: (data: RegisterData) => Promise<AuthClientResponse>;
  logout: () => Promise<void>;
  forgotPassword: (email: string) => Promise<void>;
  resetPassword: (token: string, otp: string, newPassword: string) => Promise<void>;
}

export interface AuthStatusReturn {
  isAuthenticated: boolean;
  isLoading: boolean;
}

// Hook implementation with explicit return type
export function useSession(): SessionHookReturn {
  // ...
}
```

### 6.2 Discriminated Unions for Session State

Use discriminated unions to make impossible states unrepresentable.

```tsx
type SessionState =
  | { status: 'loading'; user: null; error: null }
  | { status: 'authenticated'; user: AuthUserClient; error: null }
  | { status: 'unauthenticated'; user: null; error: Error | null };

// Consumer code gets type narrowing for free
function ProfilePage() {
  const session = useSession();

  switch (session.status) {
    case 'loading':
      return <Spinner />;
    case 'authenticated':
      // TypeScript knows session.user is AuthUserClient (non-null)
      return <div>{session.user.name}</div>;
    case 'unauthenticated':
      return <LoginForm />;
  }
}
```

**Rule:** Define `SessionState` as a discriminated union in `types.ts`. The reducer must enforce these constraints at the type level.

### 6.3 Context Typing

Type the context with `undefined` as the default to enforce the provider guard pattern.

```tsx
// The context value type — what consumers receive
export interface AuthContextValue {
  user: AuthUserClient | null;
  status: SessionStatus;
  isLoading: boolean;
  refresh: () => Promise<void>;
  lastValidation: number | null;
  client: AuthClient;
}

// Context creation — undefined means "no provider"
const AuthContext = createContext<AuthContextValue | undefined>(undefined);

// Guard function narrows the type
function useAuthContext(): AuthContextValue {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuthContext must be used within <AuthProvider>');
  }
  return context; // TypeScript knows this is AuthContextValue, not undefined
}
```

### 6.4 Generic Patterns

If the library supports user type extensions (e.g., consumers adding custom fields to the user object), use generics.

```tsx
// Allow consumers to extend the user type
export interface AuthProviderProps<TUser extends AuthUserClient = AuthUserClient> {
  children: React.ReactNode;
  client: AuthClient<TUser>;
  onSessionExpired?: () => void;
  revalidateInterval?: number;
}

export function useSession<TUser extends AuthUserClient = AuthUserClient>(): SessionHookReturn<TUser> {
  const context = useAuthContext();
  return {
    ...context,
    user: context.user as TUser | null,
  };
}

// Consumer usage with extended user type
interface MyUser extends AuthUserClient {
  organizationId: string;
  role: 'admin' | 'member';
}

function Dashboard() {
  const { user } = useSession<MyUser>();
  // user.organizationId is typed
}
```

### 6.5 Props Typing

Use `interface` for component props and `type` for union types.

```tsx
// CORRECT — interface for props (extendable)
interface AuthProviderProps {
  children: React.ReactNode;
  client: AuthClient;
  onSessionExpired?: () => void;
  revalidateInterval?: number;
}

// CORRECT — type for unions (not extendable by design)
type SessionStatus = 'loading' | 'authenticated' | 'unauthenticated';

// CORRECT — type for complex mapped types
type SessionAction =
  | { type: 'FETCH_START' }
  | { type: 'FETCH_SUCCESS'; user: AuthUserClient; timestamp: number }
  | { type: 'FETCH_ERROR'; error: Error }
  | { type: 'LOGOUT' };
```

### 6.6 Strict TypeScript Configuration

The following TypeScript settings are required for the React subpath:

```json
{
  "compilerOptions": {
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "jsx": "react-jsx",
    "moduleResolution": "bundler",
    "declaration": true,
    "declarationMap": true
  }
}
```

### 6.7 Type-Only Imports

Use `import type` for all type-only imports. This ensures types are stripped at build time and do not contribute to bundle size.

```tsx
// CORRECT — type-only import
import type { AuthClient, AuthUserClient } from '../client';
import type { SessionStatus, AuthContextValue } from './types';

// WRONG — runtime import for types
import { AuthClient, AuthUserClient } from '../client';
```

### 6.8 No `any`

Never use `any` in the library codebase. Use `unknown` for truly unknown values and narrow with type guards.

```tsx
// CORRECT
function handleError(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === 'string') return error;
  return 'An unknown error occurred';
}

// WRONG
function handleError(error: any): string {
  return error.message; // Unsafe property access
}
```

---

## 7. Error Handling

### 7.1 Error State in Hooks

Hooks that perform async operations should expose error state alongside data and loading state.

```tsx
export interface SessionHookReturn {
  user: AuthUserClient | null;
  status: SessionStatus;
  isLoading: boolean;
  error: Error | null;  // Expose the error
  refresh: () => Promise<void>;
  lastValidation: number | null;
}
```

Errors must be typed as `Error | null`, not `unknown` or `string`. Wrap unknown errors before storing them.

```tsx
function wrapError(error: unknown): Error {
  if (error instanceof Error) return error;
  if (typeof error === 'string') return new Error(error);
  return new Error('An unexpected error occurred');
}

// In reducer
case 'FETCH_ERROR':
  return {
    user: null,
    status: 'unauthenticated',
    error: wrapError(action.error),
    lastValidation: null,
  };
```

### 7.2 Error Boundaries Compatibility

This library does not ship Error Boundary components (those are application-level concerns). However, hooks must be compatible with Error Boundaries.

**Rules:**

- Hooks must not swallow errors silently. Either store them in state (for the consumer to render) or rethrow them.
- Errors during render (not in effects or event handlers) propagate to the nearest Error Boundary automatically.
- Errors in `useEffect` or event handlers do **not** propagate to Error Boundaries. Store them in state and let the consumer decide how to render them.

```tsx
// Consumer code — Error Boundary wrapping auth-dependent UI
function App() {
  return (
    <AuthProvider client={client}>
      <ErrorBoundary fallback={<AuthErrorFallback />}>
        <ProtectedRoutes />
      </ErrorBoundary>
    </AuthProvider>
  );
}
```

### 7.3 Error Recovery and Retry

Hooks should provide a mechanism for consumers to retry failed operations.

```tsx
export function useSession(): SessionHookReturn {
  const context = useAuthContext();

  return {
    user: context.user,
    status: context.status,
    isLoading: context.isLoading,
    error: context.error,
    refresh: context.refresh, // This IS the retry mechanism
    lastValidation: context.lastValidation,
  };
}

// Consumer retry pattern
function SessionStatus() {
  const { error, refresh, isLoading } = useSession();

  if (error) {
    return (
      <div role="alert">
        <p>Session error: {error.message}</p>
        <button onClick={refresh} disabled={isLoading}>
          Retry
        </button>
      </div>
    );
  }

  // ...
}
```

### 7.4 Network Error Handling

Auth operations depend on network requests. Handle network failures gracefully.

```tsx
async function performLogin(email: string, password: string): Promise<AuthClientResponse> {
  try {
    return await client.login(email, password);
  } catch (error) {
    if (error instanceof TypeError && error.message === 'Failed to fetch') {
      throw new Error('Network error. Please check your connection and try again.');
    }
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw new Error('Request was cancelled.');
    }
    throw error; // Re-throw unknown errors
  }
}
```

### 7.5 Error Codes

The library defines error codes in the shared subpath. Map server error codes to user-facing messages at the hook level.

```tsx
import { AUTH_ERROR_CODES } from '@bymax-one/nest-auth/shared';

function getErrorMessage(code: string): string {
  switch (code) {
    case AUTH_ERROR_CODES.INVALID_CREDENTIALS:
      return 'Invalid email or password.';
    case AUTH_ERROR_CODES.ACCOUNT_LOCKED:
      return 'Account locked. Please try again later.';
    case AUTH_ERROR_CODES.SESSION_EXPIRED:
      return 'Your session has expired. Please sign in again.';
    default:
      return 'An unexpected error occurred.';
  }
}
```

### 7.6 Async Error Handling in Event Handlers

Functions returned by hooks (like `login`, `logout`) are called from event handlers. These are async and must handle their own errors or let them propagate to the caller.

```tsx
// In useAuth — let errors propagate to the consumer
export function useAuth(): AuthHookReturn {
  const { client, refresh } = useAuthContext();

  const login = useCallback(
    async (email: string, password: string, options?: LoginOptions) => {
      const response = await client.login(email, password, options);
      await refresh(); // Refresh session after login
      return response;
    },
    [client, refresh],
  );

  const logout = useCallback(async () => {
    await client.logout();
    // The refresh will detect the expired session
    await refresh();
  }, [client, refresh]);

  return { login, logout, register, forgotPassword, resetPassword };
}

// Consumer handles the error
function LoginButton() {
  const { login } = useAuth();
  const [error, setError] = useState<string | null>(null);

  async function handleLogin() {
    try {
      await login(email, password);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    }
  }
}
```

---

## 8. Performance

### 8.1 When to Use `useMemo`

Use `useMemo` to cache expensive computations or to stabilize object/array references that are passed to children or used in dependency arrays.

**Use `useMemo` when:**

- Computing the context value object in `AuthProvider` (prevents all consumers from re-rendering).
- Deriving a complex value from state that is passed to memoized children.
- Creating an object that appears in a `useEffect` dependency array.

**Do NOT use `useMemo` when:**

- The computation is trivial (simple boolean check, string comparison).
- The result is a primitive value (primitives are compared by value, not reference).
- The value is only used locally and not passed down or used in dependencies.

```tsx
// CORRECT — memoize object that is the context value
const contextValue = useMemo(() => ({
  user, status, isLoading: status === 'loading', refresh, lastValidation, client,
}), [user, status, refresh, lastValidation, client]);

// CORRECT — memoize derived data passed to children
const permissions = useMemo(
  () => computePermissions(user?.roles),
  [user?.roles],
);

// UNNECESSARY — primitive value, no reference identity concern
const isAdmin = useMemo(() => user?.role === 'admin', [user?.role]);
// Just do: const isAdmin = user?.role === 'admin';
```

### 8.2 When to Use `useCallback`

Use `useCallback` to stabilize function references that are either:
- Part of a context value.
- Passed as props to memoized children.
- Listed in another hook's dependency array.

```tsx
// CORRECT — stabilize function that is in context value and dependency arrays
const refresh = useCallback(async () => {
  try {
    const session = await client.getSession();
    dispatch({ type: 'FETCH_SUCCESS', user: session.user, timestamp: Date.now() });
  } catch (error) {
    dispatch({ type: 'FETCH_ERROR', error: error as Error });
  }
}, [client]);

// CORRECT — stabilize function passed to memoized child
const handleLogout = useCallback(async () => {
  await client.logout();
  await refresh();
}, [client, refresh]);

// UNNECESSARY — function only used in local JSX, not passed down
function LoginForm() {
  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    // ...
  }
  return <form onSubmit={handleSubmit}>...</form>;
}
```

### 8.3 React 19 Compiler Impact

The React Compiler (when enabled) automatically memoizes:
- Component render output.
- Hook return values.
- Intermediate values and callbacks.

**Implications for this library:**

- Manual `useMemo` and `useCallback` are still valid — the compiler respects them and does not double-wrap.
- As the compiler matures, some manual memoization may become redundant. However, since this is a library consumed by projects that may or may not use the compiler, **keep explicit memoization for all context values and stable callbacks**.
- Write code that the compiler can analyze: no mutations, no conditional hook calls, no dynamic hook creation.

```tsx
// Compiler-friendly: pure, predictable, no side effects in render
function useAuthStatus(): AuthStatusReturn {
  const { status, isLoading } = useSession();
  return {
    isAuthenticated: status === 'authenticated',
    isLoading,
  };
}

// Compiler-unfriendly: mutation during render
function useAuthStatus(): AuthStatusReturn {
  const { status, isLoading } = useSession();
  const result = { isAuthenticated: false, isLoading };
  result.isAuthenticated = status === 'authenticated'; // Mutation!
  return result;
}
```

### 8.4 Avoiding Waterfalls

When multiple async operations depend on each other, avoid sequential waterfalls.

```tsx
// WRONG — waterfall: fetch user, then fetch permissions sequentially in separate effects
useEffect(() => {
  fetchUser().then(setUser);
}, []);

useEffect(() => {
  if (user) {
    fetchPermissions(user.id).then(setPermissions);
  }
}, [user]);

// CORRECT — fetch everything needed in a single request/effect
useEffect(() => {
  async function init() {
    const session = await client.getSession(); // Returns user + permissions
    dispatch({ type: 'FETCH_SUCCESS', user: session.user, timestamp: Date.now() });
  }
  init();
}, [client]);
```

### 8.5 Bundle Size Consciousness

This library is distributed as an npm package. Every byte matters.

- Do not import large utility libraries. Use native JavaScript APIs.
- Ensure tree-shaking works: use named exports, avoid `export default` for barrel files.
- Keep the React subpath dependency-free except for `react` (peer) and internal subpaths (`./client`, `./shared`).
- Use `import type` to avoid pulling runtime code for type-only usage.

```tsx
// CORRECT — tree-shakeable named exports in index.ts
export { AuthProvider } from './AuthProvider';
export { useSession } from './useSession';
export { useAuth } from './useAuth';
export { useAuthStatus } from './useAuthStatus';
export type { AuthProviderProps, SessionHookReturn, AuthHookReturn, AuthStatusReturn } from './types';

// WRONG — barrel re-export that defeats tree-shaking
export * from './everything';
```

---

## 9. Testing Hooks

### 9.1 Test Setup

Use `@testing-library/react` with `renderHook` for testing hooks. Use `vitest` as the test runner (project standard).

```tsx
import { renderHook, act, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AuthProvider } from './AuthProvider';
import { useSession } from './useSession';
import type { AuthClient } from '../client';
```

### 9.2 Testing Hooks That Require Context

Hooks that depend on `AuthProvider` need a wrapper.

```tsx
function createWrapper(clientOverrides?: Partial<AuthClient>) {
  const mockClient: AuthClient = {
    getSession: vi.fn().mockResolvedValue({
      user: { id: '1', name: 'Test User', email: 'test@example.com' },
    }),
    login: vi.fn().mockResolvedValue({ success: true }),
    logout: vi.fn().mockResolvedValue(undefined),
    register: vi.fn().mockResolvedValue({ success: true }),
    forgotPassword: vi.fn().mockResolvedValue(undefined),
    resetPassword: vi.fn().mockResolvedValue(undefined),
    ...clientOverrides,
  };

  function Wrapper({ children }: { children: React.ReactNode }) {
    return <AuthProvider client={mockClient}>{children}</AuthProvider>;
  }

  return { Wrapper, mockClient };
}

describe('useSession', () => {
  it('returns user data after successful session fetch', async () => {
    const { Wrapper } = createWrapper();

    const { result } = renderHook(() => useSession(), { wrapper: Wrapper });

    // Initial state is loading
    expect(result.current.isLoading).toBe(true);
    expect(result.current.status).toBe('loading');

    // Wait for session to load
    await waitFor(() => {
      expect(result.current.status).toBe('authenticated');
    });

    expect(result.current.user).toEqual({
      id: '1',
      name: 'Test User',
      email: 'test@example.com',
    });
    expect(result.current.isLoading).toBe(false);
  });
});
```

### 9.3 Testing Async Operations

Use `act` and `waitFor` for async state updates.

```tsx
describe('useAuth', () => {
  it('calls client.login and refreshes session', async () => {
    const { Wrapper, mockClient } = createWrapper();

    const { result } = renderHook(() => useAuth(), { wrapper: Wrapper });

    await waitFor(() => {
      // Wait for initial session load to complete
      expect(result.current.login).toBeDefined();
    });

    await act(async () => {
      await result.current.login('user@example.com', 'password123');
    });

    expect(mockClient.login).toHaveBeenCalledWith(
      'user@example.com',
      'password123',
      undefined,
    );
    // Session should have been refreshed
    expect(mockClient.getSession).toHaveBeenCalledTimes(2); // initial + post-login
  });

  it('propagates login errors to the caller', async () => {
    const { Wrapper } = createWrapper({
      login: vi.fn().mockRejectedValue(new Error('Invalid credentials')),
    });

    const { result } = renderHook(() => useAuth(), { wrapper: Wrapper });

    await waitFor(() => {
      expect(result.current.login).toBeDefined();
    });

    await expect(
      act(() => result.current.login('user@example.com', 'wrong')),
    ).rejects.toThrow('Invalid credentials');
  });
});
```

### 9.4 Testing the Provider Guard

```tsx
describe('useSession without provider', () => {
  it('throws when used outside AuthProvider', () => {
    // Suppress console.error for expected error
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(() => {
      renderHook(() => useSession());
    }).toThrow('useSession/useAuth must be used within <AuthProvider>');

    spy.mockRestore();
  });
});
```

### 9.5 Testing Timer-Based Effects

Test periodic revalidation by controlling timers.

```tsx
describe('AuthProvider revalidation', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('revalidates session at the configured interval', async () => {
    const { Wrapper, mockClient } = createWrapper();

    renderHook(() => useSession(), {
      wrapper: ({ children }) => (
        <AuthProvider client={mockClient as AuthClient} revalidateInterval={60_000}>
          {children}
        </AuthProvider>
      ),
    });

    // Wait for initial fetch
    await waitFor(() => {
      expect(mockClient.getSession).toHaveBeenCalledTimes(1);
    });

    // Advance time by 60 seconds
    await act(async () => {
      vi.advanceTimersByTime(60_000);
    });

    expect(mockClient.getSession).toHaveBeenCalledTimes(2);

    // Advance again
    await act(async () => {
      vi.advanceTimersByTime(60_000);
    });

    expect(mockClient.getSession).toHaveBeenCalledTimes(3);
  });
});
```

### 9.6 Mocking Fetch

When testing hooks that use `fetch` internally (through `AuthClient`), mock at the client level, not at the `fetch` level.

```tsx
// CORRECT — mock the client methods
const mockClient: AuthClient = {
  getSession: vi.fn().mockResolvedValue({ user: mockUser }),
  login: vi.fn().mockResolvedValue({ success: true }),
  // ...
};

// WRONG — mocking global fetch (too low-level, brittle)
global.fetch = vi.fn().mockResolvedValue({
  json: () => Promise.resolve({ user: mockUser }),
});
```

**Why mock at the client level:** The `AuthClient` is the boundary between the React subpath and network I/O. Mocking it gives us full control without depending on request format, headers, or URL structure.

### 9.7 Testing Derived Hooks

`useAuthStatus` derives from `useSession`. Test it through the same wrapper pattern.

```tsx
describe('useAuthStatus', () => {
  it('returns isAuthenticated: true when session is loaded', async () => {
    const { Wrapper } = createWrapper();

    const { result } = renderHook(() => useAuthStatus(), { wrapper: Wrapper });

    await waitFor(() => {
      expect(result.current.isAuthenticated).toBe(true);
    });

    expect(result.current.isLoading).toBe(false);
  });

  it('returns isAuthenticated: false when session fetch fails', async () => {
    const { Wrapper } = createWrapper({
      getSession: vi.fn().mockRejectedValue(new Error('Unauthorized')),
    });

    const { result } = renderHook(() => useAuthStatus(), { wrapper: Wrapper });

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false);
    });

    expect(result.current.isAuthenticated).toBe(false);
  });
});
```

### 9.8 Test File Organization

```
src/react/
  __tests__/
    AuthProvider.test.tsx
    useSession.test.ts
    useAuth.test.ts
    useAuthStatus.test.ts
    helpers.ts            # createWrapper, mockClient factory
```

Each hook gets its own test file. Shared test utilities go in `helpers.ts`.

---

## 10. Anti-Patterns

### 10.1 Conditional Hook Calls

```tsx
// WRONG — hooks cannot be called conditionally
function useConditionalSession(enabled: boolean) {
  if (!enabled) return null;
  const session = useSession(); // Violates Rules of Hooks
  return session;
}

// CORRECT — always call the hook, conditionally use the result
function useConditionalSession(enabled: boolean) {
  const session = useSession();
  if (!enabled) return null;
  return session;
}
```

### 10.2 useEffect as Event Handler

```tsx
// WRONG — using useEffect to respond to a user action
function LoginForm() {
  const [credentials, setCredentials] = useState<Credentials | null>(null);
  const { login } = useAuth();

  useEffect(() => {
    if (credentials) {
      login(credentials.email, credentials.password);
    }
  }, [credentials, login]);

  function handleSubmit(data: Credentials) {
    setCredentials(data); // Triggers effect, which triggers login
  }
}

// CORRECT — call the action directly in the event handler
function LoginForm() {
  const { login } = useAuth();

  async function handleSubmit(data: Credentials) {
    await login(data.email, data.password);
  }
}
```

### 10.3 Stale Closures

```tsx
// WRONG — stale closure over count
function useStaleExample() {
  const [count, setCount] = useState(0);

  useEffect(() => {
    const id = setInterval(() => {
      setCount(count + 1); // Always reads the initial count (0)
    }, 1000);
    return () => clearInterval(id);
  }, []); // Missing count dependency, but adding it recreates the interval

  return count;
}

// CORRECT — use functional updater to access latest state
function useCorrectExample() {
  const [count, setCount] = useState(0);

  useEffect(() => {
    const id = setInterval(() => {
      setCount(prev => prev + 1); // Always uses the latest value
    }, 1000);
    return () => clearInterval(id);
  }, []); // No dependency needed — we don't read count

  return count;
}
```

### 10.4 Object/Array in Dependency Array Without Memoization

```tsx
// WRONG — new object every render triggers effect on every render
function AuthWrapper({ config }: { config: AuthConfig }) {
  useEffect(() => {
    initializeAuth({ ...config, extra: 'value' });
  }, [{ ...config, extra: 'value' }]); // New object reference every time
}

// CORRECT — memoize the object
function AuthWrapper({ config }: { config: AuthConfig }) {
  const fullConfig = useMemo(
    () => ({ ...config, extra: 'value' }),
    [config],
  );

  useEffect(() => {
    initializeAuth(fullConfig);
  }, [fullConfig]);
}
```

### 10.5 Declaring Components Inside Components

```tsx
// WRONG — SessionDisplay is recreated every render, destroying its state
function AuthProvider({ children }: AuthProviderProps) {
  function SessionDisplay() {
    const { user } = useSession();
    return <div>{user?.name}</div>;
  }

  return (
    <AuthContext value={contextValue}>
      <SessionDisplay />
      {children}
    </AuthContext>
  );
}

// CORRECT — declare components at module scope
function SessionDisplay() {
  const { user } = useSession();
  return <div>{user?.name}</div>;
}

function AuthProvider({ children }: AuthProviderProps) {
  return (
    <AuthContext value={contextValue}>
      <SessionDisplay />
      {children}
    </AuthContext>
  );
}
```

### 10.6 Mutating State Directly

```tsx
// WRONG — mutation
function useAuth() {
  const { user } = useAuthContext();

  function updateRole(role: string) {
    if (user) {
      user.role = role; // Direct mutation — will not trigger re-render
    }
  }
}

// CORRECT — dispatch an action or call an API
function useAuth() {
  const { refresh } = useAuthContext();

  async function updateRole(role: string) {
    await client.updateRole(role);
    await refresh(); // Re-fetch from server, state updates via reducer
  }
}
```

### 10.7 Missing Cleanup

```tsx
// WRONG — no cleanup, causes memory leak and state update after unmount
useEffect(() => {
  const id = setInterval(refresh, 30_000);
  // Missing: return () => clearInterval(id);
}, [refresh]);

// WRONG — no abort, network request continues after unmount
useEffect(() => {
  fetch('/api/session').then(r => r.json()).then(setSession);
  // Missing: AbortController
}, []);

// CORRECT — always clean up
useEffect(() => {
  const controller = new AbortController();
  fetch('/api/session', { signal: controller.signal })
    .then(r => r.json())
    .then(setSession)
    .catch(err => {
      if (err.name !== 'AbortError') throw err;
    });
  return () => controller.abort();
}, []);
```

### 10.8 Prop Drilling Instead of Context

```tsx
// WRONG — threading auth state through multiple component layers
function App() {
  const session = useSession();
  return <Layout session={session} />;
}
function Layout({ session }) {
  return <Sidebar session={session} />;
}
function Sidebar({ session }) {
  return <UserMenu session={session} />;
}

// CORRECT — use the hook at the point of consumption
function App() {
  return <Layout />;
}
function Layout() {
  return <Sidebar />;
}
function Sidebar() {
  return <UserMenu />;
}
function UserMenu() {
  const { user } = useSession(); // Read directly from context
}
```

### 10.9 Returning Unstable References from Hooks

```tsx
// WRONG — new object on every call, breaks memoization for consumers
export function useAuth(): AuthHookReturn {
  const { client, refresh } = useAuthContext();

  return {
    login: async (email, password) => { /* ... */ },  // New function every render
    logout: async () => { /* ... */ },                  // New function every render
  };
}

// CORRECT — stabilize with useCallback
export function useAuth(): AuthHookReturn {
  const { client, refresh } = useAuthContext();

  const login = useCallback(
    async (email: string, password: string, options?: LoginOptions) => {
      const response = await client.login(email, password, options);
      await refresh();
      return response;
    },
    [client, refresh],
  );

  const logout = useCallback(async () => {
    await client.logout();
    await refresh();
  }, [client, refresh]);

  return { login, logout, register, forgotPassword, resetPassword };
}
```

### 10.10 Using `useEffect` for Derived State

```tsx
// WRONG — useEffect to sync derived state
function useAuthStatus() {
  const { status } = useSession();
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    setIsAuthenticated(status === 'authenticated');
  }, [status]);

  return { isAuthenticated };
}

// CORRECT — compute during render
function useAuthStatus() {
  const { status, isLoading } = useSession();

  return {
    isAuthenticated: status === 'authenticated',
    isLoading,
  };
}
```

---

## Quick Reference Checklist

Use this checklist when writing or reviewing React code in `@bymax-one/nest-auth/react`.

### Hooks

- [ ] Hook name starts with `use` + PascalCase descriptor.
- [ ] Non-hook utilities do NOT use the `use` prefix.
- [ ] Return type is an explicitly defined TypeScript interface.
- [ ] Multi-value returns use named objects, not tuples.
- [ ] Hook validates context availability (throws on missing provider).
- [ ] No `any` types anywhere.
- [ ] Uses `import type` for type-only imports.

### Context

- [ ] Uses `<Context value={...}>` syntax (React 19), not `<Context.Provider>`.
- [ ] Context default value is `undefined` (enables guard pattern).
- [ ] Context value is memoized with `useMemo`.
- [ ] `useCallback` wraps all functions in the context value.

### State

- [ ] Related state fields use `useReducer` or are updated atomically.
- [ ] Session status uses the discriminated union: `'loading' | 'authenticated' | 'unauthenticated'`.
- [ ] `isLoading` is derived from `status`, not maintained separately.
- [ ] All state updates are immutable.

### Effects

- [ ] Every `useEffect` with async work has a cleanup function.
- [ ] `AbortController` is used for fetch-based effects.
- [ ] No race conditions (cancelled flag or abort signal).
- [ ] Dependency array includes all reactive values used inside the effect.
- [ ] `react-hooks/exhaustive-deps` lint rule has zero suppressions.
- [ ] Separate effects for separate concerns (no monolithic effects).

### Performance

- [ ] Context value memoized with `useMemo`.
- [ ] Stable function references via `useCallback` for context-provided functions.
- [ ] No unnecessary `useMemo`/`useCallback` on primitives or local-only values.
- [ ] Named exports for tree-shaking.
- [ ] No external dependencies beyond `react` (peer) and internal subpaths.

### React 19

- [ ] No `forwardRef` — use `ref` as a prop.
- [ ] No `Context.Provider` — use `<Context value={...}>`.
- [ ] Code is compatible with React Compiler (no mutations, pure render).
- [ ] `use()` is used only with external promises or for conditional context reading.

### Testing

- [ ] Every hook has a dedicated test file.
- [ ] Tests use `renderHook` from `@testing-library/react`.
- [ ] Context-dependent hooks are tested with a wrapper providing `AuthProvider`.
- [ ] Async operations tested with `act` and `waitFor`.
- [ ] Timer-based logic tested with `vi.useFakeTimers()`.
- [ ] Mock at the `AuthClient` level, not at `fetch`.
- [ ] Provider guard (missing provider error) is tested.

### Anti-Patterns to Avoid

- [ ] No conditional hook calls.
- [ ] No `useEffect` as event handler.
- [ ] No stale closures (use functional updaters).
- [ ] No objects/arrays in dependency arrays without memoization.
- [ ] No components declared inside other components.
- [ ] No direct state mutation.
- [ ] No missing cleanup in effects.
- [ ] No `useEffect` for derived state (compute during render instead).
- [ ] No prop drilling when context is available.
- [ ] No unstable references returned from hooks.
