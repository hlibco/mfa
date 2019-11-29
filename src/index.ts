import restana from 'restana'
import speakeasy from 'speakeasy'
import QRCode from 'qrcode'

const service = restana()

interface MFA {
  created: Date
  enrolled: boolean
  secret: string
  otp: string
}
const user: { mfa?: MFA } = {
  mfa: undefined
}

service.get('/auth/secret', async (_req, res) => {
  const options = {
    issuer: `watter`,
    name: `watterapp (username@email.com)`,
    length: 64
  }

  const secret = speakeasy.generateSecret(options)
  const mfa: MFA = {
    created: new Date(),
    enrolled: false,
    secret: secret.base32,
    otp: secret.otpauth_url || ''
  }

  user.mfa = mfa

  // Get the data URL of the authenticator URL
  QRCode.toDataURL(
    mfa.otp || '',
    {
      // margin: 8,
      color: {
        dark: '#00F', // Blue dots
        light: '#FFFFFF'
        // light: '#0000' // Transparent background
      }
    },
    (err: Error | undefined, dataUrl: string) => {
      // const b64string = dataUrl.replace('data:image/png;base64,', '')
      // const binary = Buffer.from(b64string, 'base64')
      // res.send(binary, 200)

      res.send(
        `<img src="${dataUrl}" /> <br />Secret MFA code in plain text: <br />${mfa.secret}`,
        200,
        {
          'Content-Type': 'text/html'
        }
      )
    }
  )
})

service.get('/auth/validate/:token', async (req, res) => {
  if (!user.mfa) {
    throw new Error('User does not have MFA enabled')
  }
  const base32secret = user.mfa.secret
  const verified = speakeasy.totp.verify({
    secret: base32secret,
    encoding: 'base32',
    token: req.params.token,
    window: 1 // Let user enter previous totp token because of unresponsive UX.
  })

  if (verified) {
    user.mfa.enrolled = true
  } else {
    throw new Error('Invalid Token')
  }
  res.send(user, 200)
})

const port = 3000
service.start(port).then(server => {
  console.log(`Listening at http://localhost:${port}`)
})
