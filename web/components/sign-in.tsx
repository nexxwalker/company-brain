import { dmSans125ClassName, dmSansClassName } from "@lib/fonts"
const cardStyle = {
	boxShadow:
		"0 2.842px 14.211px 0 rgba(0, 0, 0, 0.25), 0.711px 0.711px 0.711px 0 rgba(255, 255, 255, 0.10) inset",
}

// Local account sign-in for the self-hosted Emberspack platform.
export function SignIn() {
	return (
		<main className="flex min-h-screen items-center justify-center bg-[#05080D] px-4">
			<div
				className="w-full max-w-sm rounded-[14px] bg-[#14161A] p-6"
				style={cardStyle}
			>
				<h1
					className={dmSans125ClassName(
						"text-[20px] font-semibold text-[#FAFAFA]",
					)}
				>
					Emberspack Slack
				</h1>
				<p className={dmSansClassName("mt-2 text-[13px] text-[#8B929E]")}>
					Sign in to your self-hosted Emberspack workspace.
				</p>
				<form method="post" action="/auth/login" className="mt-6 flex flex-col gap-3">
					<input name="email" type="email" autoComplete="email" required placeholder="Email address" className="h-10 rounded-[10px] border border-[#2C313A] bg-[#0B0E13] px-3 text-[14px] text-[#FAFAFA] outline-none placeholder:text-[#737B87] focus:border-[#FAFAFA]" />
					<input name="password" type="password" autoComplete="current-password" required placeholder="Password" className="h-10 rounded-[10px] border border-[#2C313A] bg-[#0B0E13] px-3 text-[14px] text-[#FAFAFA] outline-none placeholder:text-[#737B87] focus:border-[#FAFAFA]" />
					<button type="submit" className="flex h-10 w-full items-center justify-center rounded-[10px] bg-[#FAFAFA] text-[14px] font-medium text-[#0B0E13] transition-colors hover:bg-white">
						Sign in
					</button>
				</form>
				<a href="/auth/signup" className={dmSansClassName("mt-4 block text-center text-[12px] text-[#A8B0BC] hover:text-[#FAFAFA]")}>
					Create a local account
				</a>
				<a
					href="/setup"
					className={dmSansClassName(
						"mt-4 block text-center text-[12px] text-[#737B87] hover:text-[#FAFAFA]",
					)}
				>
					Setting this deployment up? Go to setup
				</a>
			</div>
		</main>
	)
}
