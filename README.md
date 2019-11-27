# 🧰 Multi-factor Authentication Example

> This is a basic Multi-factor Authentication project.

### Scripts

#### `yarn watch`

Starts the application in development using `nodemon` and `ts-node` to do hot reloading.

#### `yarn build`

Builds the app at `build`, cleaning the folder first.

#### `yarn start:dev` or `yarn start:prod`

Starts the app in production by first building the project with `npm run build`, and then executing the compiled JavaScript at `build/index.js`.

### API Endpoints

##### /auth/secret

Renders the QR Code to be scanned in by Google Authenticator.

##### /auth/validate/:token

Validates the time based token generated by Google Authenticator.
