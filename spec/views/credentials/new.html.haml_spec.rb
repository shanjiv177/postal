# frozen_string_literal: true

require "rails_helper"

RSpec.describe "credentials/new", type: :view do
  let(:user) { create(:user, admin: true) }
  let(:organization) { create(:organization, owner: user) }
  let(:server) { create(:server, organization: organization) }

  before do
    assign(:organization, organization)
    assign(:server, server)
    assign(:credential, server.credentials.build)
    without_partial_double_verification do
      allow(view).to receive(:organization).and_return(organization)
      allow(view).to receive(:current_user).and_return(user)
      allow(view).to receive(:page_title).and_return(["Postal"])
    end
  end

  it "shows the allowed senders field" do
    render
    expect(rendered).to include("credential[allowed_senders_text]")
    expect(rendered).to include("Allowed senders")
  end
end
