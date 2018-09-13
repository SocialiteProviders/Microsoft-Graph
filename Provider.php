<?php

namespace SocialiteProviders\Graph;

use Laravel\Socialite\Two\ProviderInterface;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;

class Provider extends AbstractProvider implements ProviderInterface
{
    /**
     * Unique Provider Identifier.
     */
    const IDENTIFIER = 'GRAPH';

    /**
     * {@inheritdoc}
     */
    protected $scopes = ['User.Read'];

    /**
     * The separating character for the requested scopes.
     *
     * @var string
     */
    protected $scopeSeparator = ' ';

    /**
     * Allows you to override the tenant id that the provider is configured
     * with.
     *
     * @param string $tenantId
     *
     * @return \SocialiteProviders\Graph\Provider
     */
    public function setTenantId($tenantId)
    {
        $this->config = array_merge($this->config, [
            'tenant_id' => $tenantId,
        ]);

        return $this;
    }

    /**
     * Returns the configured tenant that we're authenticating with, or common
     * if one is not configured.
     *
     * @return string
     */
    private function getTenantId()
    {
        return $this->getConfig('tenant_id', 'common');
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase(
            sprintf(
                'https://login.microsoftonline.com/%s/oauth2/v2.0/authorize',
                $this->getTenantId()
            ),
            $state
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return sprintf(
            'https://login.microsoftonline.com/%s/oauth2/v2.0/token',
            $this->getTenantId()
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        $response = $this->getHttpClient()->get('https://graph.microsoft.com/v1.0/me/', [
            'headers' => [
                'Authorization' => 'Bearer '.$token,
            ],
        ]);

        return json_decode($response->getBody(), true);
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        /*
            Mapping default Laravel user keys and the keys that are nested in $user->user in response. Modify as needed.
        */
        return (new User())->setRaw($user)->map([
            'id'                => $user['id'],
            'name'              => array_get($user, 'displayName'),
            'email'             => array_get($user, 'mail'),

            'businessPhones'    => array_get($user, 'businessPhones'),
            'displayName'       => array_get($user, 'displayName'),
            'givenName'         => array_get($user, 'givenName'),
            'jobTitle'          => array_get($user, 'jobTitle'),
            'mail'              => array_get($user, 'mail'),
            'mobilePhone'       => array_get($user, 'mobilePhone'),
            'officeLocation'    => array_get($user, 'officeLocation'),
            'preferredLanguage' => array_get($user, 'preferredLanguage'),
            'surname'           => array_get($user, 'surname'),
            'userPrincipalName' => array_get($user, 'userPrincipalName'),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenFields($code)
    {
        return array_merge(parent::getTokenFields($code), [
            'grant_type' => 'authorization_code',
        ]);
    }
}
