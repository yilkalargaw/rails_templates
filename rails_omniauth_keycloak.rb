def source_paths
  [__dir__]
end

# Helper methods
def say_step(step, message)
  say "\n[Step #{step}] #{message}", :cyan
end

def say_warning(message)
  say "WARNING: #{message}", :yellow
end

def say_success(message)
  say "SUCCESS: #{message}", :green
end

# Main template
say_step 1, "Adding required gems..."
gem 'devise', '~> 4.9'
gem 'omniauth_openid_connect', '~> 0.8'
gem 'dotenv-rails', '~> 3.1'
gem 'image_processing', '~> 1.2'
gem 'omniauth-rails_csrf_protection', '~> 1.0', '>= 1.0.2'

# Development gems
gem_group :development do
  gem 'annotate'
  gem 'rubocop', require: false
end

after_bundle do
  # Initialize git
  git :init
  git add: "."
  git commit: "-m 'Initial commit'"

  # --------------------------
  # Devise + Keycloak Setup
  # --------------------------
  say_step 2, "Setting up Devise and configuring default URL options..."
  generate 'devise:install'

  # Configure default URL options in config/application.rb
  environment 'config.action_mailer.default_url_options = { host: "localhost", port: 3000 }',
              env: 'development' # Keep this for mailer

  application do
    <<-RUBY
      config.action_mailer.default_url_options = { host: 'localhost', port: 3000 }
      config.default_url_options = { host: 'localhost', port: 3000 }
    RUBY
  end

  say_step 3, "Creating User model..."
  generate 'devise User'
  generate 'migration AddOmniauthFieldsToUsers provider:string uid:string name:string image:text'

  say_step 4, "Configuring environment..."
  remove_file '.env' # Remove the old .env
  create_file '.env', <<~ENV
    # Keycloak Configuration
    KEYCLOAK_HOST=localhost
    KEYCLOAK_PORT=8080
    KEYCLOAK_SCHEME=http
    KEYCLOAK_REALM=realm_name
    KEYCLOAK_CLIENT_ID=client_id
    KEYCLOAK_CLIENT_SECRET=client_secret
    APP_HOSTNAME=app_hostname

  ENV

  remove_file '.env.example' # Remove the old .env.example
  create_file '.env.example', <<~ENV
    # Keycloak Configuration
    KEYCLOAK_HOST=
    KEYCLOAK_PORT=
    KEYCLOAK_SCHEME=http
    KEYCLOAK_REALM=
    KEYCLOAK_CLIENT_ID=
    KEYCLOAK_CLIENT_SECRET=
    APP_HOSTNAME=

  ENV

  say_step 5, "Creating devise.rb initializer with OmniAuth config (using environment variables)..."
  remove_file 'config/initializers/devise.rb'
  create_file 'config/initializers/devise.rb', <<~RUBY
    # frozen_string_literal: true

    Devise.setup do |config|
      config.mailer_sender = 'please-change-me-at-config-initializers-devise@example.com'

      require 'devise/orm/active_record'
      config.case_insensitive_keys = [:email]
      config.strip_whitespace_keys = [:email]
      config.skip_session_storage = [:http_auth]
      config.stretches = Rails.env.test? ? 1 : 12
      config.reconfirmable = true
      config.expire_all_remember_me_on_sign_out = true
      config.password_length = 6..128
      config.email_regexp = /\A[^@\s]+@[^@\s]+\z/
      config.reset_password_within = 6.hours
      config.sign_in_after_reset_password = true
      config.sign_out_via = :delete
      config.responder.error_status = :unprocessable_entity
      config.responder.redirect_status = :see_other

      keycloak_issuer_url = "\#{ENV['KEYCLOAK_SCHEME']}://\#{ENV['KEYCLOAK_HOST']}:\#{ENV['KEYCLOAK_PORT']}/realms/\#{ENV['KEYCLOAK_REALM']}"

      # ==> OmniAuth
      config.omniauth :openid_connect, {
        name: :keycloak,
        scope: [:openid, :profile, :email],
        response_type: :code,
        uid_field: "preferred_username",
        discovery: false, # Disable auto-discovery
        issuer: keycloak_issuer_url,
        client_options: {
          site: "\#{ENV['KEYCLOAK_SCHEME']}://\#{ENV['KEYCLOAK_HOST']}:\#{ENV['KEYCLOAK_PORT']}",
          port: ENV['KEYCLOAK_PORT'].to_i,
          scheme: ENV['KEYCLOAK_SCHEME'],
          host: ENV['KEYCLOAK_HOST'],
          identifier: ENV['KEYCLOAK_CLIENT_ID'],
          secret: ENV['KEYCLOAK_CLIENT_SECRET'],
          redirect_uri: "http://\#{ENV['APP_HOSTNAME']}/users/auth/keycloak/callback",
          authorization_endpoint: "\#{keycloak_issuer_url}/protocol/openid-connect/auth",
          token_endpoint: "\#{keycloak_issuer_url}/protocol/openid-connect/token",
          userinfo_endpoint: "\#{keycloak_issuer_url}/protocol/openid-connect/userinfo",
          jwks_uri: "\#{keycloak_issuer_url}/protocol/openid-connect/certs",
        },
        ssl: { verify: false } # Disable SSL verification (for local testing only)
      }
    end
  RUBY

  say_step 6, "Creating OAuth callback controller..."
  create_file 'app/controllers/users/omniauth_callbacks_controller.rb', <<~RUBY
    class Users::OmniauthCallbacksController < Devise::OmniauthCallbacksController
      def keycloak
        @user = User.from_omniauth(request.env['omniauth.auth'])

        if @user.persisted?
          sign_in_and_redirect @user, event: :authentication
          set_flash_message(:notice, :success, kind: 'Keycloak') if is_navigational_format?
        else
          redirect_to new_user_registration_url,
            alert: @user.errors.full_messages.join("\\n")
        end
      end

      def failure
        redirect_to root_path,
          alert: "Authentication failed: \#{params[:error_description] || 'Unknown error'}"
      end
    end
  RUBY

  say_step 7, "Creating User model with OmniAuth support..."
  remove_file 'app/models/user.rb'
  create_file 'app/models/user.rb', <<~RUBY
    class User < ApplicationRecord
      # Include default devise modules. Others available are:
      # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
      devise :database_authenticatable, :registerable,
             :recoverable, :rememberable, :validatable,
             :omniauthable, omniauth_providers: [:keycloak]

      def self.from_omniauth(auth)
        where(provider: auth.provider, uid: auth.uid).first_or_create do |user|
          user.email = auth.info.email
          user.password = Devise.friendly_token[0, 20]
          user.name = auth.info.name
          user.image = auth.info.image
        end
      end
    end
  RUBY

  # --------------------------
  # Add OmniAuth routes
  # --------------------------
  say_step 8, "Adding OmniAuth routes to config/routes.rb..."
  gsub_file 'config/routes.rb', /(devise_for :users)/, '\1, controllers: { omniauth_callbacks: "users/omniauth_callbacks" }, path_names: { omniauth_authorize: "auth" }'

  # --------------------------
  # Application Scaffolding (Generic)
  # --------------------------
  say_step 9, "Generating a basic Home controller and view..."
  generate 'controller Home index'
  route "root to: 'home#index'"

  # --------------------------
  # Final Setup
  # --------------------------
  say_step 10, "Running migrations..."
  rails_command 'db:migrate'

  say_step 11, "Setting up login view..."
  create_file 'app/views/devise/sessions/new.html.erb', <<~ERB, force: true
    <h2>Log in</h2>

    <%= form_for(resource, as: resource_name, url: session_path(resource_name)) do |f| %>
      <div class="field">
        <%= f.label :email %><br />
        <%= f.email_field :email, autofocus: true, autocomplete: "email" %>
      </div>

      <div class="field">
        <%= f.label :password %><br />
        <%= f.password_field :password, autocomplete: "current-password" %>
      </div>

      <% if devise_mapping.rememberable? %>
        <div class="field">
          <%= f.check_box :remember_me %>
          <%= f.label :remember_me %>
        </div>
      <% end %>

      <div class="actions">
        <%= f.submit "Log in" %>
      </div>
    <% end %>

    <% # Remove the automatic OmniAuth links/buttons %>
    <% #= render "devise/shared/omniauth_links" %>
    <%= render "devise/shared/links" %>
  ERB

  say_step 12, "Configuring host for development environment..."
  insert_into_file 'config/environments/development.rb', after: "Rails.application.configure do\n" do
    <<~RUBY
      config.hosts << "localhost"
      config.hosts << ".localhost"
      config.hosts << "127.0.0.1"
      config.hosts << "[::1]"
    RUBY
  end

  say_step 13, "Ensure protect_from_forgery in ApplicationController..."
  inject_into_class 'app/controllers/application_controller.rb', 'ApplicationController' do
    <<~RUBY
      protect_from_forgery with: :exception
    RUBY
  end

  git add: "."
  git commit: "-m 'Add Devise, Keycloak auth (env vars), basic Home controller, configure dev host, ensure CSRF protection'"

  say_success "\nDevelopment environment setup complete!"
  puts <<~NEXTSTEPS
    Next steps:
    1. Configure Keycloak:
       - Update .env with the right Keycloak credentials (host, port, scheme, realm, client ID, secret)
       - Set up client in Keycloak with matching settings and the redirect URI: http://localhost:3000/users/auth/keycloak/callback

    2. Start the server:
       rails server

    3. Access the app:
       http://localhost:3000

    4. Test authentication:
       - Regular login (register first)
       - Keycloak login

    5. Define your application's models, controllers, and views. You can start by generating resources as needed:
       rails generate resource YourModel field1:type field2:type ...
  NEXTSTEPS
end
