import eslint from "@eslint/js"
import tseslint from "typescript-eslint"
import cdkPlugin from "eslint-plugin-awscdk";


export default [
	eslint.configs.recommended,
	{
		files: ["**/*.{js,mjs,cjs,ts}"],
		languageOptions: {
			parser: tseslint.parser,
			parserOptions: {
				projectService: true,
				tsconfigRootDir: import.meta.dirname,
			},
		},
	},
	...tseslint.configs.strictTypeChecked,
	...tseslint.configs.stylisticTypeChecked,
	cdkPlugin.configs.recommended,
	{
		ignores: [
			"node_modules/**",
			"**/dist/**",
			"build/**",
			".turbo/**",
			".next/**",
			"**/*.mjs",
			"cdk.out/**",
			"functions/**",
			"graphql/**",
			"rest/**",
			"temp/**",
		],
	},
	{
		files: ["**/*.{ts,tsx}"],
		rules: {
			"awscdk/no-variable-construct-id": "off",
			"awscdk/no-construct-stack-suffix": "off",
			"@typescript-eslint/no-unused-vars": [
				"warn",
				{
					argsIgnorePattern: "^_",
					varsIgnorePattern: "^_",
					caughtErrorsIgnorePattern: "^_",
				},
			],
		},
	},

]
