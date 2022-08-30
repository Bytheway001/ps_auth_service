# frozen_string_literal: true

require_relative "ps_auth_service/version"

module PsAuthService
  class Error < StandardError; end
  class AuthServer < BaseService
    def initialize(params,headers)
        @action = params[:action]
        @controller=params[:controller].sub('api/v1/','')
        @authorization = headers["Authorization"]
        @apikey = headers['Api-Key']
        @api = ::Faraday.new(url: ENV["AUTH_SERVER_URL"])
    end

    def call
      if @authorization
          validate_token_on_auth_server
      elsif @apikey
          validate_api_key_on_auth_server
      else
          raise "No authorization Token Provided"
      end
    end

    def find_user
      User.where(token: @authorization).last
    end
  
    def validate_token_on_auth_server
      res = @api.get("oauth/token/info") do |req|
          req.headers['Authorization'] = "#{@authorization}"
          req.params['_controller'] = @controller
          req.params['_action'] = @action
          req.params['_app_name'] = 'quoti'
      end
      
      @token_response = JSON.parse(res.body)
  
      if res.status != 200 
          raise AuthServerException.new('Auth Server Failure',@token_response)
      end
    end

    def validate_api_key_on_auth_server
      res = @api.get("/authorize_app") do |req|
          req.headers['Api-Key'] = "#{@apikey}"
          req.params['_controller'] = @controller
          req.params['_action'] = @action
          req.params['_app_name'] = 'quoti'
      end
      if res.status != 200
          @token_response = JSON.parse(res.body)
          raise AuthServerException.new
      end
    end
  end
end
