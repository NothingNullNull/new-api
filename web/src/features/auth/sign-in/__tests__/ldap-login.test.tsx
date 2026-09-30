/*
Copyright (C) 2023-2026 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please contact support@quantumnous.com
*/
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
} from '@tanstack/react-router'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'

import { api } from '@/lib/api'
import { useAuthStore, type AuthBundle } from '@/stores/auth-store'

import { UserAuthForm } from '../components/user-auth-form'

const bundle: AuthBundle = {
  access_token: 'ldap-access-token',
  token_type: 'Bearer',
  access_expires_at: 9999999999,
  user: { id: 42, username: 'directory-user', role: 1 },
  session: {
    sid: 'ldap-session',
    current: true,
    login_method: 'ldap',
    ip: '',
    user_agent: '',
    created_at: 1,
    last_active_at: 1,
    expires_at: 9999999999,
  },
}

function renderLogin(status: Record<string, unknown> = {}) {
  vi.spyOn(api, 'get').mockResolvedValue({
    data: {
      success: true,
      data: { ldap_enabled: true, password_login_enabled: false, ...status },
    },
  })
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  const root = createRootRoute({ component: Outlet })
  const loginRoute = createRoute({
    getParentRoute: () => root,
    path: '/sign-in',
    component: () => <UserAuthForm redirectTo='/dashboard' />,
  })
  const dashboardRoute = createRoute({
    getParentRoute: () => root,
    path: '/dashboard',
    component: () => <h1>Signed in</h1>,
  })
  const otpRoute = createRoute({
    getParentRoute: () => root,
    path: '/otp',
    component: () => <h1>Second factor required</h1>,
  })
  const router = createRouter({
    routeTree: root.addChildren([loginRoute, dashboardRoute, otpRoute]),
    history: createMemoryHistory({ initialEntries: ['/sign-in'] }),
  })
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  )
  return { user: userEvent.setup(), queryClient }
}

beforeEach(() => {
  localStorage.clear()
  sessionStorage.clear()
  useAuthStore.getState().auth.reset('complete')
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  useAuthStore.getState().auth.reset('complete')
})

it('LDAP-only sign in submits directory credentials and establishes the new browser session', async () => {
  const post = vi.spyOn(api, 'post').mockResolvedValue({
    data: { success: true, data: bundle },
  })
  const { user } = renderLogin()
  const button = await screen.findByRole('button', {
    name: 'Sign in with LDAP',
  })
  await user.type(screen.getByLabelText('Username or Email'), 'directory-user')
  await user.type(screen.getByLabelText('Password'), 'directory-password')
  await user.click(button)
  expect(
    await screen.findByRole('heading', { name: 'Signed in' })
  ).toBeVisible()
  expect(post).toHaveBeenCalledWith(
    '/api/user/login/ldap?turnstile=',
    { username: 'directory-user', password: 'directory-password' },
    { skipAuthRefresh: true }
  )
  expect(useAuthStore.getState().auth.session?.login_method).toBe('ldap')
})

it('LDAP primary authentication with MFA routes to verification without establishing a session', async () => {
  const challenge = {
    require_verification: true,
    flow_token: 'ldap-verification-flow',
    expires_at: Math.floor(Date.now() / 1000) + 300,
    methods: [{ method: '2fa', available: true }],
  }
  vi.spyOn(api, 'post').mockResolvedValue({
    data: { success: true, data: challenge },
  })
  const { user } = renderLogin()
  const button = await screen.findByRole('button', {
    name: 'Sign in with LDAP',
  })
  await user.type(screen.getByLabelText('Username or Email'), 'directory-user')
  await user.type(screen.getByLabelText('Password'), 'directory-password')
  await user.click(button)
  expect(
    await screen.findByRole('heading', { name: 'Second factor required' })
  ).toBeVisible()
  expect(useAuthStore.getState().auth.session).toBeNull()
  expect(
    useAuthStore.getState().auth.pendingLoginVerification?.challenge.flow_token
  ).toBe(challenge.flow_token)
})

it('disabled LDAP does not expose the directory sign-in action', async () => {
  renderLogin({ ldap_enabled: false, password_login_enabled: true })
  await screen.findByRole('button', { name: 'Sign in' })
  expect(
    screen.queryByRole('button', { name: 'Sign in with LDAP' })
  ).not.toBeInTheDocument()
})

it('empty LDAP credentials fail form validation without contacting the directory', async () => {
  const post = vi.spyOn(api, 'post')
  const { user } = renderLogin()
  await user.click(
    await screen.findByRole('button', { name: 'Sign in with LDAP' })
  )
  await waitFor(() =>
    expect(screen.getByLabelText('Password')).toHaveAttribute(
      'aria-invalid',
      'true'
    )
  )
  expect(post).not.toHaveBeenCalled()
})

it('LDAP sign in requires legal consent before directory credentials can be submitted', async () => {
  const post = vi.spyOn(api, 'post')
  const { user } = renderLogin({ user_agreement_enabled: true })
  const button = await screen.findByRole('button', {
    name: 'Sign in with LDAP',
  })
  expect(button).toBeDisabled()
  await user.click(screen.getByRole('checkbox'))
  expect(button).toBeEnabled()
  expect(post).not.toHaveBeenCalled()
})

it('Enter submits LDAP-only credentials through the directory login endpoint', async () => {
  const post = vi
    .spyOn(api, 'post')
    .mockResolvedValue({ data: { success: true, data: bundle } })
  const { user } = renderLogin()
  await screen.findByRole('button', { name: 'Sign in with LDAP' })
  await user.type(screen.getByLabelText('Username or Email'), 'directory-user')
  await user.type(
    screen.getByLabelText('Password'),
    'directory-password{Enter}'
  )
  expect(
    await screen.findByRole('heading', { name: 'Signed in' })
  ).toBeVisible()
  expect(post).toHaveBeenCalledWith(
    '/api/user/login/ldap?turnstile=',
    expect.anything(),
    expect.anything()
  )
})

it('an in-flight LDAP request disables both login actions and a failed request restores them', async () => {
  let complete: (value: unknown) => void = () => {}
  const post = vi.spyOn(api, 'post').mockImplementation(
    () =>
      new Promise((resolve) => {
        complete = resolve
      })
  )
  const { user } = renderLogin({ password_login_enabled: true })
  const ldap = await screen.findByRole('button', { name: 'Sign in with LDAP' })
  const password = screen.getByRole('button', { name: 'Sign in' })
  await user.type(screen.getByLabelText('Username or Email'), 'directory-user')
  await user.type(screen.getByLabelText('Password'), 'directory-password')
  await user.click(ldap)
  await waitFor(() => expect(post).toHaveBeenCalledTimes(1))
  expect(ldap).toBeDisabled()
  expect(password).toBeDisabled()
  await user.click(password)
  expect(post).toHaveBeenCalledTimes(1)
  complete({
    data: { success: false, message: 'Directory credentials rejected' },
  })
  await waitFor(() => expect(ldap).toBeEnabled())
  expect(password).toBeEnabled()
  expect(useAuthStore.getState().auth.session).toBeNull()
})
