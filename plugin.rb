# frozen_string_literal: true
# name: discourse-discord-2fa-unlock
# about: Allow users to sign in with Discord while enforcing 2FA
# version: 0.0.1
# author: Wolftallemo
# url: https://github.com/Wolftallemo/discourse-discord-2fa-unlock

after_initialize do
  module MFABypass
    def user_found(user)
      mode = SiteSetting.discord_2fa_bypass.downcase

      if @auth_result.extra_data[:provider] != "discord" or
        !user.has_any_second_factor_methods_enabled? or
        mode == "nobody"
        return super
      end

      associated_user = UserAssociatedAccount.find_by(provider_name: "discord", user: user)

      unless associated_user.extra["raw_info"]["mfa_enabled"]
        return super
      end

      if user.staff? &&
        mode == "everyone except staff" ||
        user.admin? &&
        mode == "everyone except admins"
        return super
      end

      def user.has_any_second_factor_methods_enabled?
        false
      end

      super(user)

    end

    protected :user_found
  end

  class Users::OmniauthCallbacksController
    prepend MFABypass
  end
end
