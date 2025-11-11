// app/login/page.tsx
'use client';
import { useState, useEffect } from 'react';
import { supabase } from '../../../lib/supabaseClient';

export default function LoginPage() {
	const [email, setEmail] = useState('');
	const [password, setPassword] = useState('');
	const [message, setMessage] = useState('');
	const [loading, setLoading] = useState(false);
	const [showPassword, setShowPassword] = useState(false);
	const [showForgotPassword, setShowForgotPassword] = useState(false);
	const [errors, setErrors] = useState<{ email?: string; password?: string }>({});
	const [logoLoaded, setLogoLoaded] = useState(false);
	const [logoError, setLogoError] = useState(false);

	// Check if logo exists on component mount
	useEffect(() => {
		const img = new Image();
		img.src = '/elma-logo.png';
		img.onload = () => {
			setLogoLoaded(true);
			setLogoError(false);
		};
		img.onerror = () => {
			setLogoLoaded(false);
			setLogoError(true);
		};
	}, []);

	function validateFields(): boolean {
		const nextErrors: { email?: string; password?: string } = {};
		const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
		if (!emailOk) nextErrors.email = 'Enter a valid email';
		if (password.length < 1) nextErrors.password = 'Password is required';
		setErrors(nextErrors);
		return Object.keys(nextErrors).length === 0;
	}

	async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
		event.preventDefault();
		setMessage('');
		setErrors({});
		
		if (!validateFields()) return;
		
		setLoading(true);
		try {
			const { data, error } = await supabase.auth.signInWithPassword({ email, password });
			if (error) throw error;
			
			// Check if password change is required (first login with temporary password)
			if (data.user?.user_metadata?.requires_password_change) {
				// Clear the flag from user metadata
				await supabase.auth.updateUser({
					data: { requires_password_change: false }
				});
				
				// Redirect to password reset page
				setMessage('Please set your permanent password...');
				setTimeout(() => {
					window.location.href = '/auth/callback?type=recovery';
				}, 400);
			} else {
				setMessage('Login successful! Redirecting...');
				// brief delay to show message, then redirect
				setTimeout(() => {
					window.location.href = '/dashboard';
				}, 400);
			}
		} catch (err) {
			const error = err as Error;
			const errorMessage = error?.message || 'Something went wrong';
			if (errorMessage.includes('Invalid login credentials')) {
				setMessage('Invalid email or password. Please try again. If your account is inactive, please contact your administrator.');
			} else if (errorMessage.includes('User not found') || errorMessage.includes('not found')) {
				setMessage('Account not found. Please contact your administrator.');
			} else {
				setMessage('Failed: ' + errorMessage);
			}
		} finally {
			setLoading(false);
		}
	}

	async function handleForgotPassword(event: React.FormEvent<HTMLFormElement>) {
		event.preventDefault();
		setMessage('');
		setErrors({});
		
		if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
			setErrors({ email: 'Enter a valid email' });
			return;
		}
		
		setLoading(true);
		try {
			// First, check if user exists and is active
			let checkData: any = null;
			try {
				const checkResponse = await fetch('/api/users/check-email', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
					},
					body: JSON.stringify({ email }),
				});

				if (!checkResponse.ok) {
					console.error('Check email API error:', checkResponse.status, checkResponse.statusText);
					// Continue with password reset attempt even if check fails
				} else {
					checkData = await checkResponse.json();
					
					if (checkData.error) {
						console.error('Check email API returned error:', checkData.error);
						// Continue with password reset attempt
					} else if (!checkData.exists) {
						setMessage('This email address is not registered. Please contact your administrator to create an account.');
						setLoading(false);
						return;
					} else if (!checkData.isActive) {
						setMessage('Your account is inactive. Please contact your administrator to activate your account before resetting your password.');
						setLoading(false);
						return;
					} else if (!checkData.existsInAuth) {
						setMessage('Your account exists but is not fully set up in the authentication system. Please contact your administrator for assistance.');
						setLoading(false);
						return;
					}
				}
			} catch (checkErr) {
				console.error('Error checking user email:', checkErr);
				// Continue with password reset attempt even if check fails
			}

			// User exists and is active - proceed with password reset
			const { error, data } = await supabase.auth.resetPasswordForEmail(email, {
				redirectTo: `${window.location.origin}/auth/callback`,
			});
			
			if (error) {
				// Extract error information safely
				const errorMessage = error?.message || String(error) || '';
				const errorStatus = error?.status || (error as any)?.code || 0;
				const errorName = error?.name || '';
				
				// Enhanced error logging
				console.error('Password reset error:', {
					error: error,
					message: errorMessage,
					status: errorStatus,
					name: errorName,
					email: email,
					errorType: typeof error,
					errorString: String(error),
					errorJSON: JSON.stringify(error, Object.getOwnPropertyNames(error), 2),
					errorKeys: error ? Object.keys(error) : [],
				});
				
				// Handle specific error cases
				if (errorMessage.includes('User not found') || errorStatus === 400) {
					setMessage('This email address is not registered. Please contact your administrator to create an account.');
				} else if (errorMessage.includes('Email rate limit') || errorMessage.includes('rate limit') || errorStatus === 429) {
					setMessage('Too many password reset requests. Please wait a few minutes and try again.');
				} else if (errorStatus === 500 || errorMessage.includes('Error sending recovery email') || errorMessage.includes('recovery email') || errorMessage.includes('SMTP') || errorMessage.includes('534')) {
					// Since we've verified the user exists and is active, this is likely an email configuration issue
					setMessage('Unable to send recovery email. The email service is not configured in Supabase. Please contact your administrator to configure SMTP settings in the Supabase dashboard (Settings → Auth → SMTP Settings).');
				} else if (errorMessage.includes('email') || errorStatus >= 500) {
					setMessage('Email service error. Please contact your administrator to verify email service configuration.');
				} else if (errorMessage) {
					setMessage(`Failed: ${errorMessage}`);
				} else {
					setMessage('Unable to send recovery email. Please contact your administrator to verify email service configuration in Supabase (Settings → Auth → SMTP Settings).');
				}
				return;
			}
			
			// Success - email sent
			setMessage('A password reset link has been sent to your email. Please check your inbox, spam folder, and Promotions tab. If you don\'t receive it within 5 minutes, the email service may be experiencing issues. Please contact your administrator or check Supabase Auth Logs.');
			setShowForgotPassword(false);
		} catch (err) {
			const error = err as Error & { status?: number };
			console.error('Password reset exception:', err);
			
			// Provide user-friendly error messages
			if (error.status === 500) {
				setMessage('Server error: Unable to send recovery email. Please contact your administrator to verify email service configuration.');
			} else if (error.status === 400) {
				setMessage('Invalid request. Please check your email address and try again.');
			} else {
				setMessage(`Failed: ${error?.message || 'Unable to send recovery email. Please try again later or contact support.'}`);
			}
		} finally {
			setLoading(false);
		}
	}

	return (
		<div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-900 via-purple-900 to-blue-900 px-4 py-12">
			{/* Background decorative elements */}
			<div className="absolute inset-0 overflow-hidden pointer-events-none">
				<div className="absolute top-1/4 left-1/4 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl"></div>
				<div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl"></div>
			</div>

			<div className="relative w-full max-w-md">
				{/* Login Card */}
				<div className="bg-white/95 backdrop-blur-sm rounded-2xl shadow-2xl border border-white/20 p-8 md:p-10">
					{/* Logo Section - Complete logo image with icon and text */}
					<div className="text-center mb-8">
						<div className="flex justify-center mb-6">
							{/* Logo Image - Only show if loaded successfully */}
							{logoLoaded ? (
								<img 
									src="/elma-logo.png"
									alt="elma - defines purity"
									className="h-auto w-auto max-w-[200px] md:max-w-[240px] object-contain mx-auto"
									style={{ 
										maxHeight: '180px',
										imageRendering: 'auto'
									}}
								/>
							) : null}
							{/* Fallback message if logo image not found */}
							{logoError && !logoLoaded && (
								<div className="flex flex-col items-center justify-center text-center text-gray-600 w-full">
									<div className="mb-3">
										<svg className="w-12 h-12 mx-auto text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
											<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
										</svg>
									</div>
									<p className="mb-2 font-semibold text-gray-700">Logo Image Not Found</p>
									<p className="text-xs mb-3 text-gray-500">
										Please place your logo file in the <code className="bg-gray-200 px-2 py-1 rounded text-gray-800 font-mono">public</code> folder:
									</p>
									<div className="bg-gray-100 px-4 py-2 rounded-lg mb-2">
										<p className="text-xs font-mono text-gray-800">
											<strong>public/elma-logo.png</strong>
										</p>
									</div>
									<p className="text-xs text-gray-400">
										Supported formats: PNG, SVG, JPG, JPEG
									</p>
								</div>
							)}
						</div>
					</div>

					{/* Welcome Message */}
					<div className="text-center mb-8">
						<h2 className="text-2xl font-bold text-gray-900 mb-2">Welcome Back</h2>
						<p className="text-gray-600 text-sm">Sign in to access your dashboard</p>
					</div>

					{showForgotPassword ? (
						<form onSubmit={handleForgotPassword} className="space-y-6">
							<div className="text-center mb-6">
								<h3 className="text-xl font-semibold text-gray-900 mb-2">Reset Password</h3>
								<p className="text-sm text-gray-600">Enter your email to receive a password reset link</p>
							</div>
							
							<div>
								<label htmlFor="forgot-email" className="block text-sm font-medium text-gray-700 mb-2">
									Email Address
								</label>
								<input
									id="forgot-email"
									type="email"
									placeholder="you@example.com"
									value={email}
									onChange={e => setEmail(e.target.value)}
									required
									className={`w-full px-4 py-3 rounded-lg border transition-all focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent ${
										errors.email ? 'border-red-300 bg-red-50' : 'border-gray-300 bg-white'
									}`}
								/>
								{errors.email && (
									<p className="mt-1 text-sm text-red-600">{errors.email}</p>
								)}
							</div>

							<button
								type="submit"
								disabled={loading}
								className="w-full py-3 px-4 bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-semibold rounded-lg shadow-lg hover:shadow-xl transform hover:scale-[1.02] transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
							>
								{loading ? (
									<span className="flex items-center justify-center gap-2">
										<svg className="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
											<circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
											<path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
										</svg>
										Sending...
									</span>
								) : (
									'Send Reset Link'
								)}
							</button>

							<button
								type="button"
								onClick={() => {
									setShowForgotPassword(false);
									setMessage('');
									setErrors({});
								}}
								className="w-full py-2.5 px-4 border border-gray-300 text-gray-700 font-medium rounded-lg hover:bg-gray-50 transition-colors"
							>
								Back to Login
							</button>
						</form>
					) : (
						<form onSubmit={handleSubmit} className="space-y-6">
							{/* Email Field */}
							<div>
								<label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-2">
									Email Address
								</label>
								<input
									id="email"
									type="email"
									placeholder="you@example.com"
									value={email}
									onChange={e => setEmail(e.target.value)}
									required
									autoComplete="email"
									className={`w-full px-4 py-3 rounded-lg border transition-all focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent ${
										errors.email ? 'border-red-300 bg-red-50' : 'border-gray-300 bg-white hover:border-gray-400'
									}`}
								/>
								{errors.email && (
									<p className="mt-1 text-sm text-red-600">{errors.email}</p>
								)}
							</div>

							{/* Password Field */}
							<div>
								<label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-2">
									Password
								</label>
								<div className="relative">
									<input
										id="password"
										type={showPassword ? 'text' : 'password'}
										placeholder="••••••••"
										value={password}
										onChange={e => setPassword(e.target.value)}
										required
										autoComplete="current-password"
										className={`w-full px-4 py-3 pr-12 rounded-lg border transition-all focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent ${
											errors.password ? 'border-red-300 bg-red-50' : 'border-gray-300 bg-white hover:border-gray-400'
										}`}
									/>
									<button
										type="button"
										onClick={() => setShowPassword(v => !v)}
										className="absolute right-3 top-1/2 -translate-y-1/2 p-1.5 text-gray-500 hover:text-gray-700 transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-1 rounded"
										aria-label={showPassword ? 'Hide password' : 'Show password'}
										title={showPassword ? 'Hide password' : 'Show password'}
									>
										{showPassword ? (
											<svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
												<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
											</svg>
										) : (
											<svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
												<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
												<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
											</svg>
										)}
									</button>
								</div>
								{errors.password && (
									<p className="mt-1 text-sm text-red-600">{errors.password}</p>
								)}
							</div>

							{/* Forgot Password Link */}
							<div className="flex justify-end">
								<button
									type="button"
									onClick={() => setShowForgotPassword(true)}
									className="text-sm text-indigo-600 hover:text-indigo-800 font-medium transition-colors"
								>
									Forgot password?
								</button>
							</div>

							{/* Submit Button */}
							<button
								type="submit"
								disabled={loading}
								className="w-full py-3.5 px-4 bg-gradient-to-r from-indigo-600 via-purple-600 to-indigo-600 text-white font-semibold rounded-lg shadow-lg hover:shadow-xl transform hover:scale-[1.02] transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
							>
								{loading ? (
									<span className="flex items-center justify-center gap-2">
										<svg className="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
											<circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
											<path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
										</svg>
										Signing in...
									</span>
								) : (
									'Sign In'
								)}
							</button>
						</form>
					)}

					{/* Message Display */}
					{message && (
						<div className={`mt-6 p-4 rounded-lg text-sm ${
							message.includes('successful') || message.includes('sent') || message.includes('Redirecting')
								? 'bg-green-50 text-green-800 border border-green-200'
								: message.includes('Please set')
								? 'bg-blue-50 text-blue-800 border border-blue-200'
								: 'bg-red-50 text-red-800 border border-red-200'
						}`}>
							<div className="flex items-center gap-2">
								{message.includes('successful') || message.includes('sent') || message.includes('Redirecting') || message.includes('Please set') ? (
									<svg className="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
										<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
									</svg>
								) : (
									<svg className="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
										<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
									</svg>
								)}
								<span>{message}</span>
							</div>
						</div>
					)}

					{/* Footer Note */}
					<div className="mt-8 text-center">
						<p className="text-xs text-gray-500">
							Don't have an account? Contact your IT administrator.
						</p>
					</div>
				</div>
			</div>
		</div>
	);
}
