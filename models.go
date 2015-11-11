package ghost

// Snapchat Structs

// SnapchatError represents a Snapchat Error.
type SnapchatError struct {
	Message string `json:"message"`
	Status  int    `json:"status"`
	Logged  bool   `json:"logged"`
}

// StudySettings provides a study setting event struct.
type StudySettings struct {
	RegisterHideSkipPhone `json:"REGISTER_HIDE_SKIP_PHONE"`
}

// RegisterHideSkipPhone provides a study setting.
type RegisterHideSkipPhone struct {
	Experimentid string `json:"experimentId"`
}

// Register provides a register struct when registering a snapchat account.
type Register struct {
	AuthToken                    string   `json:"auth_token"`
	DefaultUsername              string   `json:"default_username"`
	DefaultUsernameStatus        bool     `json:"default_username_status"`
	Email                        string   `json:"email"`
	Logged                       bool     `json:"logged"`
	ShouldSendTextToVerifyNumber bool     `json:"should_send_text_to_verify_number"`
	SnapchatPhoneNumber          string   `json:"snapchat_phone_number"`
	UserID                       string   `json:"user_id"`
	UsernameSuggestions          []string `json:"username_suggestions"`
}

// Discover represents an array of Snapchat Discover channels.
type Discover struct {
	Channels []struct {
		Name                        string `json:"name"`
		Position                    int    `json:"position"`
		StoriesPagePosition         int    `json:"stories_page_position"`
		PromotedStoriesPagePosition int    `json:"promoted_stories_page_position"`
		PublisherName               string `json:"publisher_name"`
		PublisherFormalName         string `json:"publisher_formal_name"`
		FilledIcon                  string `json:"filled_icon"`
		InvertedIcon                string `json:"inverted_icon"`
		LoadingIcon                 string `json:"loading_icon"`
		IntroMovie                  string `json:"intro_movie"`
		PrimaryColor                string `json:"primary_color"`
		SecondaryColor              string `json:"secondary_color"`
		EditionID                   int64  `json:"edition_id"`
		DsnapsData                  []struct {
			URL     string `json:"url"`
			DsnapID int64  `json:"dsnap_id"`
			Hash    string `json:"hash"`
			Color   string `json:"color"`
			AdType  int    `json:"ad_type"`
		} `json:"dsnaps_data"`
		IntroVideoAdMetadata struct {
			AdUnitID            string `json:"ad_unit_id"`
			TargetingParameters struct {
				Position    string `json:"position"`
				Region      string `json:"region"`
				Edition     string `json:"edition"`
				Channel     string `json:"channel"`
				ChannelType string `json:"channel_type"`
				Publisher   string `json:"publisher"`
			} `json:"targeting_parameters"`
		} `json:"intro_video_ad_metadata"`
		Sponsored bool `json:"sponsored"`
	} `json:"channels"`
	GenerationTs int64 `json:"generation_ts"`
}

// Updates represents the entire Snapchat account.
type Updates struct {
	UpdatesResponse struct {
		FriendmojiDict struct {
			Replay struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"replay"`
			NumberOneBfForTwoWeeks struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"number_one_bf_for_two_weeks"`
			YourNumberOneBfIsTheirNumberOneBf struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"your_number_one_bf_is_their_number_one_bf"`
			OnFire struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"on_fire"`
			R2611Fe0F struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"r2611fe0f"`
			NewFriend struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"new_friend"`
			NumberOneBfForTwoMonths struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"number_one_bf_for_two_months"`
			YouAreOneOfThereBfButTheyAreNotYour struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"you_are_one_of_there_bf_but_they_are_not_your"`
			HundredStreak struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"hundred_streak"`
			Robin struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"robin"`
			Catwomen struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"catwomen"`
			YouShareBf struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"you_share_BF"`
			OneOfYourBf struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"one_of_your_bf"`
			Batman struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"batman"`
			Rd83Ddc7D struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"rd83ddc7d"`
			Rd83Dde4C struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"rd83dde4c"`
			Rd83Ddc8E struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"rd83ddc8e"`
			NumberOneBf struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"number_one_bf"`
		} `json:"friendmoji_dict"`
		Score                    int           `json:"score"`
		EnableSaveStoryToGallery bool          `json:"enable_save_story_to_gallery"`
		NumberOfBestFriends      int           `json:"number_of_best_friends"`
		Received                 int           `json:"received"`
		IsVerifiedUser           bool          `json:"is_verified_user"`
		Requests                 []interface{} `json:"requests"`
		Username                 string        `json:"username"`
		Sent                     int           `json:"sent"`
		FeatureSettings          struct {
			ReplaySnaps      bool `json:"replay_snaps"`
			FrontFacingFlash bool `json:"front_facing_flash"`
			PayReplaySnaps   bool `json:"pay_replay_snaps"`
			SpecialText      bool `json:"special_text"`
			SmartFilters     bool `json:"smart_filters"`
			PowerSaveMode    bool `json:"power_save_mode"`
			SwipeCashMode    bool `json:"swipe_cash_mode"`
			TravelMode       bool `json:"travel_mode"`
		} `json:"feature_settings"`
		SnapP                   int    `json:"snap_p"`
		AddedFriendsTimestamp   int    `json:"added_friends_timestamp"`
		AllowedToUseCash        string `json:"allowed_to_use_cash"`
		IsCashActive            bool   `json:"is_cash_active"`
		SearchableByPhoneNumber bool   `json:"searchable_by_phone_number"`
		StudySettings           struct {
			Videopublicencodingstudy         string `json:"videoPublicEncodingStudy"`
			ServerEndpointMigration          string `json:"SERVER_ENDPOINT_MIGRATION"`
			ChatTCP                          string `json:"CHAT_TCP"`
			DiscoverV2                       string `json:"DISCOVER_V2"`
			TableLoadTest                    string `json:"table_load_test"`
			EdgeCacheRouting                 string `json:"EDGE_CACHE_ROUTING"`
			VideoMetadata                    string `json:"VIDEO_METADATA"`
			Sessionrecreationprohibittime    string `json:"SessionRecreationProhibitTime"`
			DiscoverQuality                  string `json:"DISCOVER_QUALITY"`
			AdaptiveTimeoutV2                string `json:"ADAPTIVE_TIMEOUT_V2"`
			MigrationFallbackDisableIos      string `json:"MIGRATION_FALLBACK_DISABLE_IOS"`
			AddlivePresence                  string `json:"ADDLIVE_PRESENCE"`
			DiscoverQualityV2                string `json:"DISCOVER_QUALITY_V2"`
			ContinuousLocationUpdate         string `json:"CONTINUOUS_LOCATION_UPDATE"`
			ProtoIos                         string `json:"PROTO_IOS"`
			PhoneVerificationLatePromptV2    string `json:"PHONE_VERIFICATION_LATE_PROMPT_V2"`
			Prompt                           string `json:"PROMPT"`
			SessionRecreationAvoidThrottling string `json:"SESSION_RECREATION_AVOID_THROTTLING"`
			Gzip                             string `json:"GZIP"`
			PingServiceV2                    string `json:"PING_SERVICE_V2"`
			PhoneVerificationLatePrompt      string `json:"PHONE_VERIFICATION_LATE_PROMPT"`
			MigrationFallbackDurationAndroid string `json:"MIGRATION_FALLBACK_DURATION_ANDROID"`
			LongformPrioritization           string `json:"LONGFORM_PRIORITIZATION"`
			Storyonboard                     string `json:"storyOnboard"`
			ServerEndpointMigrationIos       string `json:"SERVER_ENDPOINT_MIGRATION_IOS"`
			WarmupBackupConnection           string `json:"WARMUP_BACKUP_CONNECTION"`
			SessionRecreationForeground      string `json:"SESSION_RECREATION_FOREGROUND"`
			DeltaResponse                    string `json:"DELTA_RESPONSE"`
			Arxan                            string `json:"ARXAN"`
			StoriesViewOrganization          string `json:"STORIES_VIEW_ORGANIZATION"`
			StoriesNewLoadingUI              string `json:"STORIES_NEW_LOADING_UI"`
			ConnectionPool                   string `json:"CONNECTION_POOL"`
			DelayAppLaunch                   string `json:"DELAY_APP_LAUNCH"`
			AdMediaDownloadPriority          string `json:"AD_MEDIA_DOWNLOAD_PRIORITY"`
			AuthStoryBlobBatching            string `json:"AUTH_STORY_BLOB_BATCHING"`
			StoryExplorer                    string `json:"STORY_EXPLORER"`
			SnapLoading                      string `json:"SNAP_LOADING"`
			Admanager                        string `json:"AdManager"`
			BackgroundFetchV2                string `json:"BACKGROUND_FETCH_V2"`
			Earlyuploadsnaps                 string `json:"EarlyUploadSnaps"`
			Spdy                             string `json:"SPDY"`
			MigrationFallbackDisableAndroid  string `json:"MIGRATION_FALLBACK_DISABLE_ANDROID"`
			DlHighPriorityInContextMsg       string `json:"DL_HIGH_PRIORITY_IN_CONTEXT_MSG"`
			ImageTranscoding                 string `json:"IMAGE_TRANSCODING"`
			Cloudfront                       string `json:"Cloudfront"`
			DownloadManager                  string `json:"DOWNLOAD_MANAGER"`
			CrossStoryThumbnailBatching      string `json:"CROSS_STORY_THUMBNAIL_BATCHING"`
			Quic                             string `json:"QUIC"`
			PreviewVerticalSwipeIos          string `json:"PREVIEW_VERTICAL_SWIPE_IOS"`
			DefaultBatterySaveModeOn         string `json:"DEFAULT_BATTERY_SAVE_MODE_ON"`
			SessionTimeoutV98                string `json:"SESSION_TIMEOUT_V98"`
			Videoencodingstudy               string `json:"videoEncodingStudy"`
			QuicCache                        string `json:"QUIC_CACHE"`
			MigrationFallbackDurationIos     string `json:"MIGRATION_FALLBACK_DURATION_IOS"`
			DownloadManagerRequestAndroid    string `json:"DOWNLOAD_MANAGER_REQUEST_ANDROID"`
			LogNeedsloveFriends              string `json:"LOG_NEEDSLOVE_FRIENDS"`
			UploadOptimize                   string `json:"UPLOAD_OPTIMIZE"`
			SessionTimeout                   string `json:"SESSION_TIMEOUT"`
			Proto                            string `json:"PROTO"`
			StoryLoading                     string `json:"STORY_LOADING"`
			EncryptMedia                     string `json:"encrypt_media"`
		} `json:"study_settings"`
		AuthToken                     string `json:"auth_token"`
		ImageCaption                  bool   `json:"image_caption"`
		LastAddressBookUpdatedDate    int    `json:"last_address_book_updated_date"`
		IsTwoFaEnabled                bool   `json:"is_two_fa_enabled"`
		QrPath                        string `json:"qr_path"`
		RawThumbnailUploadEnabled     bool   `json:"raw_thumbnail_upload_enabled"`
		EnableLensesAndroid           bool   `json:"enable_lenses_android"`
		Email                         string `json:"email"`
		ResetDisabledTranscodingState struct {
			ShouldReset bool `json:"should_reset"`
			Timestamp   int  `json:"timestamp"`
		} `json:"reset_disabled_transcoding_state"`
		ContactsResyncRequest         int    `json:"contacts_resync_request"`
		ShouldSendTextToVerifyNumber  bool   `json:"should_send_text_to_verify_number"`
		ShouldCallToVerifyNumber      bool   `json:"should_call_to_verify_number"`
		Mobile                        string `json:"mobile"`
		EnableVideoTranscodingAndroid bool   `json:"enable_video_transcoding_android"`
		Birthday                      string `json:"birthday"`
		Targeting                     struct {
			AppVersionGreaterThanOrEqualTo913 bool   `json:"app_version_greater_than_or_equal_to_9.13"`
			AppVersionGreaterThanOrEqualTo914 bool   `json:"app_version_greater_than_or_equal_to_9.14"`
			AppVersionGreaterThanOrEqualTo915 bool   `json:"app_version_greater_than_or_equal_to_9.15"`
			AppVersionGreaterThanOrEqualTo916 bool   `json:"app_version_greater_than_or_equal_to_9.16"`
			Age                               int    `json:"age"`
			AppVersion                        string `json:"app_version"`
			AppVersionGreaterThanOrEqualTo910 bool   `json:"app_version_greater_than_or_equal_to_9.10"`
			Gender                            string `json:"gender"`
			AppVersionGreaterThanOrEqualTo911 bool   `json:"app_version_greater_than_or_equal_to_9.11"`
			AppVersionGreaterThanOrEqualTo912 bool   `json:"app_version_greater_than_or_equal_to_9.12"`
		} `json:"targeting"`
		Logged                   bool          `json:"logged"`
		EnableImageTranscoding   bool          `json:"enable_image_transcoding"`
		SeenTooltips             []interface{} `json:"seen_tooltips"`
		StoryPrivacy             string        `json:"story_privacy"`
		GaussianBlurLevelAndroid int           `json:"gaussian_blur_level_android"`
		FriendmojiMutableDict    struct {
			Replay struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				Title           string `json:"title"`
				EmojiDesc       string `json:"emoji_desc"`
				EmojiPickerDesc string `json:"emoji_picker_desc"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"replay"`
			NumberOneBfForTwoWeeks struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				Title           string `json:"title"`
				EmojiDesc       string `json:"emoji_desc"`
				EmojiPickerDesc string `json:"emoji_picker_desc"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"number_one_bf_for_two_weeks"`
			YourNumberOneBfIsTheirNumberOneBf struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				Title           string `json:"title"`
				EmojiDesc       string `json:"emoji_desc"`
				EmojiPickerDesc string `json:"emoji_picker_desc"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"your_number_one_bf_is_their_number_one_bf"`
			OnFire struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				Title           string `json:"title"`
				EmojiDesc       string `json:"emoji_desc"`
				EmojiPickerDesc string `json:"emoji_picker_desc"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"on_fire"`
			YouShareBf struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				Title           string `json:"title"`
				EmojiDesc       string `json:"emoji_desc"`
				EmojiPickerDesc string `json:"emoji_picker_desc"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"you_share_BF"`
			OneOfYourBf struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				Title           string `json:"title"`
				EmojiDesc       string `json:"emoji_desc"`
				EmojiPickerDesc string `json:"emoji_picker_desc"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"one_of_your_bf"`
			NumberOneBf struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				Title           string `json:"title"`
				EmojiDesc       string `json:"emoji_desc"`
				EmojiPickerDesc string `json:"emoji_picker_desc"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"number_one_bf"`
			NewFriend struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				Title           string `json:"title"`
				EmojiDesc       string `json:"emoji_desc"`
				EmojiPickerDesc string `json:"emoji_picker_desc"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"new_friend"`
			NumberOneBfForTwoMonths struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				Title           string `json:"title"`
				EmojiDesc       string `json:"emoji_desc"`
				EmojiPickerDesc string `json:"emoji_picker_desc"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"number_one_bf_for_two_months"`
			YouAreOneOfThereBfButTheyAreNotYour struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				Title           string `json:"title"`
				EmojiDesc       string `json:"emoji_desc"`
				EmojiPickerDesc string `json:"emoji_picker_desc"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"you_are_one_of_there_bf_but_they_are_not_your"`
		} `json:"friendmoji_mutable_dict"`
		TranscodingProfileLevelConfigurationAndroid bool     `json:"transcoding_profile_level_configuration_android"`
		DeviceToken                                 string   `json:"device_token"`
		CashCustomerID                              string   `json:"cash_customer_id"`
		UserID                                      string   `json:"user_id"`
		MobileVerificationKey                       string   `json:"mobile_verification_key"`
		VideoFiltersEnabled                         bool     `json:"video_filters_enabled"`
		Recents                                     []string `json:"recents"`
		RequireRefreshingProfileMedia               bool     `json:"require_refreshing_profile_media"`
		NotificationSoundSetting                    string   `json:"notification_sound_setting"`
		FriendmojiReadOnlyDict                      struct {
			Robin struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"robin"`
			HundredStreak struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"hundred_streak"`
			Catwomen struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"catwomen"`
			R2611Fe0F struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"r2611fe0f"`
			Batman struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"batman"`
			Rd83Ddc7D struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"rd83ddc7d"`
			Rd83Dde4C struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"rd83dde4c"`
			Rd83Ddc8E struct {
				Type            int    `json:"type"`
				Source          string `json:"source"`
				DefaultType     int    `json:"default_type"`
				DefaultVal      string `json:"default_val"`
				EmojiLegendRank int    `json:"emoji_legend_rank"`
			} `json:"rd83ddc8e"`
		} `json:"friendmoji_read_only_dict"`
		ClientProperties struct {
			SnapcashTosV2Accepted  string `json:"snapcash_tos_v2_accepted"`
			SnapcashNewTosAccepted string `json:"snapcash_new_tos_accepted"`
		} `json:"client_properties"`
		SnapchatPhoneNumber        string        `json:"snapchat_phone_number"`
		VerifiedSharedPublications []interface{} `json:"verified_shared_publications"`
		CountryCode                string        `json:"country_code"`
		SpeedFiltersEnabledAndroid bool          `json:"speed_filters_enabled_android"`
		CashProvider               string        `json:"cash_provider"`
		CurrentTimestamp           int64         `json:"current_timestamp"`
		CanViewMatureContent       bool          `json:"can_view_mature_content"`
		Industries                 []string      `json:"industries"`
	} `json:"updates_response"`
	FriendsResponse struct {
		Bests            []interface{} `json:"bests"`
		FriendsSyncToken string        `json:"friends_sync_token"`
		Friends          []struct {
			NeedsLove           bool   `json:"needs_love"`
			CanSeeCustomStories bool   `json:"can_see_custom_stories"`
			Expiration          int64  `json:"expiration"`
			DontDecayThumbnail  bool   `json:"dont_decay_thumbnail"`
			Direction           string `json:"direction"`
			Name                string `json:"name"`
			FriendmojiString    string `json:"friendmoji_string"`
			SharedStoryID       string `json:"shared_story_id"`
			IsSharedStory       bool   `json:"is_shared_story"`
			Display             string `json:"display"`
			Venue               string `json:"venue"`
			Type                int    `json:"type"`
		} `json:"friends"`
		FriendsSyncType string        `json:"friends_sync_type"`
		AddedFriends    []interface{} `json:"added_friends"`
	} `json:"friends_response"`
	StoriesResponse struct {
		MyStoriesWithCollabs []interface{} `json:"my_stories_with_collabs"`
		MatureContentText    struct {
			Title   string `json:"title"`
			Message string `json:"message"`
			YesText string `json:"yes_text"`
			NoText  string `json:"no_text"`
		} `json:"mature_content_text"`
		MyVerifiedStories  []interface{} `json:"my_verified_stories"`
		MyStories          []interface{} `json:"my_stories"`
		FriendStoriesDelta bool          `json:"friend_stories_delta"`
		FriendStories      []struct {
			MatureContent bool   `json:"mature_content"`
			Username      string `json:"username"`
			Stories       []struct {
				Story struct {
					ID            string  `json:"id"`
					Username      string  `json:"username"`
					MatureContent bool    `json:"mature_content"`
					ClientID      string  `json:"client_id"`
					Timestamp     int64   `json:"timestamp"`
					MediaID       string  `json:"media_id"`
					MediaKey      string  `json:"media_key"`
					MediaIv       string  `json:"media_iv"`
					ThumbnailIv   string  `json:"thumbnail_iv"`
					MediaType     int     `json:"media_type"`
					Time          float64 `json:"time"`
					Zipped        bool    `json:"zipped"`
					StoryFilterID string  `json:"story_filter_id"`
					TimeLeft      int     `json:"time_left"`
					IsShared      bool    `json:"is_shared"`
					MediaURL      string  `json:"media_url"`
					ThumbnailURL  string  `json:"thumbnail_url"`
					NeedsAuth     bool    `json:"needs_auth"`
					AdCanFollow   bool    `json:"ad_can_follow"`
				} `json:"story"`
				Viewed bool `json:"viewed"`
			} `json:"stories"`
		} `json:"friend_stories"`
		MyGroupStories []interface{} `json:"my_group_stories"`
	} `json:"stories_response"`
	ConversationsResponse []struct {
		Participants         []string `json:"participants"`
		LastInteractionTs    int64    `json:"last_interaction_ts"`
		PendingChatsFor      []string `json:"pending_chats_for"`
		PendingReceivedSnaps []struct {
			Sn    string  `json:"sn"`
			T     int     `json:"t"`
			Timer float64 `json:"timer"`
			ID    string  `json:"id"`
			St    int     `json:"st"`
			M     int     `json:"m"`
			Ts    int64   `json:"ts"`
			Sts   int64   `json:"sts"`
		} `json:"pending_received_snaps"`
		ID                   string `json:"id"`
		ConversationMessages struct {
			MessagingAuth struct {
				Payload string `json:"payload"`
				Mac     string `json:"mac"`
			} `json:"messaging_auth"`
			Messages []struct {
				ChatMessage struct {
					Body struct {
						Type string `json:"type"`
						Text string `json:"text"`
					} `json:"body"`
					ChatMessageID string `json:"chat_message_id"`
					SeqNum        int    `json:"seq_num"`
					Timestamp     int64  `json:"timestamp"`
					Header        struct {
						From   string   `json:"from"`
						To     []string `json:"to"`
						ConvID string   `json:"conv_id"`
					} `json:"header"`
					Type string `json:"type"`
					ID   string `json:"id"`
				} `json:"chat_message"`
				IterToken string `json:"iter_token"`
			} `json:"messages"`
		} `json:"conversation_messages"`
		ConversationState struct {
			UserSequences struct {
				Teamsnapchat int `json:"teamsnapchat"`
			} `json:"user_sequences"`
			UserChatReleases struct {
				Teamsnapchat struct {
					Teamsnapchat int `json:"teamsnapchat"`
				} `json:"teamsnapchat"`
			} `json:"user_chat_releases"`
			UserSnapReleases struct {
			} `json:"user_snap_releases"`
		} `json:"conversation_state"`
		LastSnap struct {
			Sn    string  `json:"sn"`
			T     int     `json:"t"`
			Timer float64 `json:"timer"`
			ID    string  `json:"id"`
			St    int     `json:"st"`
			M     int     `json:"m"`
			Ts    int64   `json:"ts"`
			Sts   int64   `json:"sts"`
		} `json:"last_snap"`
		LastChatActions struct {
			LastWriter         string `json:"last_writer"`
			LastWriteTimestamp int64  `json:"last_write_timestamp"`
			LastWriteType      string `json:"last_write_type"`
		} `json:"last_chat_actions"`
	} `json:"conversations_response"`
	Discover struct {
		Compatibility          string `json:"compatibility"`
		GetChannels            string `json:"get_channels"`
		VideoCatalog           string `json:"video_catalog"`
		AdVideoCatalog         string `json:"ad_video_catalog"`
		ResourceParameterName  string `json:"resource_parameter_name"`
		ResourceParameterValue string `json:"resource_parameter_value"`
		SharingEnabled         bool   `json:"sharing_enabled"`
	} `json:"discover"`
	MessagingGatewayInfo struct {
		GatewayAuthToken struct {
			Payload string `json:"payload"`
			Mac     string `json:"mac"`
		} `json:"gateway_auth_token"`
		GatewayServer string `json:"gateway_server"`
	} `json:"messaging_gateway_info"`
	BackgroundFetchSecretKey string `json:"background_fetch_secret_key"`
	IdentityCheckResponse    struct {
		IsEmailVerified                    bool `json:"is_email_verified"`
		RequirePhonePasswordConfirmed      bool `json:"require_phone_password_confirmed"`
		RedGearDurationMillis              int  `json:"red_gear_duration_millis"`
		SuggestedFriendFetchThresholdHours int  `json:"suggested_friend_fetch_threshold_hours"`
		IsAddNearbyEnabled                 bool `json:"is_add_nearby_enabled"`
		IsHighAccuracyRequiredForNearby    bool `json:"is_high_accuracy_required_for_nearby"`
		TrophyCase                         struct {
			Response []struct {
				Label   string `json:"label"`
				Unicode string `json:"unicode"`
				Stages  []struct {
					Label             string `json:"label"`
					Unicode           string `json:"unicode"`
					Status            string `json:"status"`
					AchievedTimestamp int    `json:"achieved_timestamp"`
				} `json:"stages"`
			} `json:"response"`
		} `json:"trophy_case"`
	} `json:"identity_check_response"`
	Sponsored struct {
		Style struct {
			TextSize         string `json:"text_size"`
			Color            string `json:"color"`
			DropshadowColor  string `json:"dropshadow_color"`
			DropshadowOffset struct {
				X string `json:"x"`
				Y string `json:"y"`
			} `json:"dropshadow_offset"`
		} `json:"style"`
		DefaultValues struct {
			ViewRect struct {
				X      string `json:"x"`
				Y      string `json:"y"`
				Width  string `json:"width"`
				Height string `json:"height"`
			} `json:"view_rect"`
			Alignment            string `json:"alignment"`
			Position             string `json:"position"`
			Hmargin              string `json:"hmargin"`
			Vmargin              string `json:"vmargin"`
			Text                 string `json:"text"`
			SponsoredText        string `json:"sponsored_text"`
			SponsoredChannelText string `json:"sponsored_channel_text"`
			TimeBeforeFadeout    int    `json:"time_before_fadeout"`
		} `json:"default_values"`
	} `json:"sponsored"`
}

// StorySnap holds a single snap in a collection of stories.
type StorySnap struct {
	StoryResponse struct {
		JSON struct {
			Story struct {
				ID                 string  `json:"id"`
				Username           string  `json:"username"`
				MatureContent      bool    `json:"mature_content"`
				ClientID           string  `json:"client_id"`
				Timestamp          int64   `json:"timestamp"`
				MediaID            string  `json:"media_id"`
				MediaKey           string  `json:"media_key"`
				MediaIv            string  `json:"media_iv"`
				ThumbnailIv        string  `json:"thumbnail_iv"`
				MediaType          int     `json:"media_type"`
				Time               float64 `json:"time"`
				CaptionTextDisplay string  `json:"caption_text_display"`
				Zipped             bool    `json:"zipped"`
				IsShared           bool    `json:"is_shared"`
				IsTitleSnap        bool    `json:"is_title_snap"`
				NeedsAuth          bool    `json:"needs_auth"`
				AdCanFollow        bool    `json:"ad_can_follow"`
				Orientation        int     `json:"orientation"`
				IsFrontFacing      bool    `json:"is_front_facing"`
				TimeLeft           int     `json:"time_left"`
				MediaURL           string  `json:"media_url"`
				ThumbnailURL       string  `json:"thumbnail_url"`
			} `json:"story"`
		} `json:"json"`
		Success bool `json:"success"`
	} `json:"story_response"`
	SnapResponse struct {
		Snaps struct {
			EfrenPrice095B struct {
				ID        string `json:"id"`
				Timestamp int64  `json:"timestamp"`
				Pending   bool   `json:"pending"`
			} `json:"efren.price095b"`
		} `json:"snaps"`
		Success bool `json:"success"`
	} `json:"snap_response"`
}

// Stories holds an entire 24 hour Snapchat story from the user's account.
type Stories struct {
	ServerInfo struct {
		ServerLatency string `json:"server_latency"`
	} `json:"server_info"`
	MyStoriesWithCollabs []interface{} `json:"my_stories_with_collabs"`
	MatureContentText    struct {
		Title   string `json:"title"`
		Message string `json:"message"`
		YesText string `json:"yes_text"`
		NoText  string `json:"no_text"`
	} `json:"mature_content_text"`
	MyVerifiedStories []interface{} `json:"my_verified_stories"`
	MyStories         []struct {
		StoryNotes []interface{} `json:"story_notes"`
		Story      struct {
			ID                 string  `json:"id"`
			Username           string  `json:"username"`
			MatureContent      bool    `json:"mature_content"`
			ClientID           string  `json:"client_id"`
			Timestamp          int64   `json:"timestamp"`
			MediaID            string  `json:"media_id"`
			MediaKey           string  `json:"media_key"`
			MediaIv            string  `json:"media_iv"`
			ThumbnailIv        string  `json:"thumbnail_iv"`
			MediaType          int     `json:"media_type"`
			Time               float64 `json:"time"`
			CaptionTextDisplay string  `json:"caption_text_display"`
			Zipped             bool    `json:"zipped"`
			StoryFilterID      string  `json:"story_filter_id"`
			TimeLeft           int     `json:"time_left"`
			IsShared           bool    `json:"is_shared"`
			MediaURL           string  `json:"media_url"`
			ThumbnailURL       string  `json:"thumbnail_url"`
			NeedsAuth          bool    `json:"needs_auth"`
			AdCanFollow        bool    `json:"ad_can_follow"`
		} `json:"story"`
		StoryExtras struct {
			ViewCount       int `json:"view_count"`
			ScreenshotCount int `json:"screenshot_count"`
		} `json:"story_extras"`
	} `json:"my_stories"`
	FriendStoriesDelta bool `json:"friend_stories_delta"`
	FriendStories      []struct {
		AllowStoryExplorer bool   `json:"allow_story_explorer"`
		DisplayName        string `json:"display_name"`
		MatureContent      bool   `json:"mature_content"`
		Username           string `json:"username"`
		Stories            []struct {
			Story struct {
				ID                 string  `json:"id"`
				Username           string  `json:"username"`
				MatureContent      bool    `json:"mature_content"`
				ClientID           string  `json:"client_id"`
				Timestamp          int64   `json:"timestamp"`
				MediaID            string  `json:"media_id"`
				MediaKey           string  `json:"media_key"`
				MediaIv            string  `json:"media_iv"`
				ThumbnailIv        string  `json:"thumbnail_iv"`
				MediaType          int     `json:"media_type"`
				Time               float64 `json:"time"`
				CaptionTextDisplay string  `json:"caption_text_display"`
				Zipped             bool    `json:"zipped"`
				StoryFilterID      string  `json:"story_filter_id"`
				Unlockables        []struct {
					UnlockableID   string `json:"unlockable_id"`
					UnlockableType string `json:"unlockable_type"`
				} `json:"unlockables"`
				TimeLeft     int    `json:"time_left"`
				IsShared     bool   `json:"is_shared"`
				MediaURL     string `json:"media_url"`
				ThumbnailURL string `json:"thumbnail_url"`
				NeedsAuth    bool   `json:"needs_auth"`
				AdCanFollow  bool   `json:"ad_can_follow"`
			} `json:"story"`
			Viewed bool `json:"viewed"`
		} `json:"stories"`
		AdPlacementMetadata struct {
			AdInsertionConfig struct {
				FirstOnResume   int `json:"first_on_resume"`
				Interval        int `json:"interval"`
				MinSnapsAfterAd int `json:"min_snaps_after_ad"`
				FirstOnStart    int `json:"first_on_start"`
			} `json:"ad_insertion_config"`
			AdRequestConfig struct {
				FirstPosition    int `json:"first_position"`
				MinimumRemaining int `json:"minimum_remaining"`
				Timeout          int `json:"timeout"`
			} `json:"ad_request_config"`
			TargetingParameters struct {
				Genre       string `json:"genre"`
				ChannelType string `json:"channel_type"`
			} `json:"targeting_parameters"`
			AdUnitID string `json:"ad_unit_id"`
		} `json:"ad_placement_metadata"`
		SharedID             string `json:"shared_id"`
		HasCustomDescription bool   `json:"has_custom_description"`
		Thumbnails           struct {
			Unviewed struct {
				NeedsAuth bool   `json:"needs_auth"`
				URL       string `json:"url"`
			} `json:"unviewed"`
			Viewed struct {
				NeedsAuth bool   `json:"needs_auth"`
				URL       string `json:"url"`
			} `json:"viewed"`
		} `json:"thumbnails"`
		IsLocal bool `json:"is_local"`
	} `json:"friend_stories"`
	MyGroupStories []interface{} `json:"my_group_stories"`
}

// LensSchedule holds a struct coresponding to the Snapchat Lens feature.
type LensSchedule struct {
	Schedule struct {
		Two0151024T00000700 []struct {
			FilterID              string   `json:"filter_id"`
			Image                 string   `json:"image"`
			Position              []string `json:"position"`
			Priority              int      `json:"priority"`
			IsDynamicGeofilter    bool     `json:"is_dynamic_geofilter"`
			IsSponsored           bool     `json:"is_sponsored"`
			SponsoredSlugPosition string   `json:"sponsored_slug_position"`
			SponsoredSlug         struct {
				Alignment         string `json:"alignment"`
				Position          string `json:"position"`
				Text              string `json:"text"`
				TimeBeforeFadeout int    `json:"time_before_fadeout"`
			} `json:"sponsored_slug"`
			HideSponsoredSlug bool `json:"hide_sponsored_slug"`
			IsFeatured        bool `json:"is_featured"`
			IsLens            bool `json:"is_lens"`
			LensData          struct {
				Code         string `json:"code"`
				IconLink     string `json:"icon_link"`
				LensLink     string `json:"lens_link"`
				LensChecksum string `json:"lens_checksum"`
				ConfigPath   string `json:"config_path"`
			} `json:"lens_data"`
		} `json:"2015-10-24T00:00-0700"`
		Two0151025T00000700 []struct {
			FilterID              string   `json:"filter_id"`
			Image                 string   `json:"image"`
			Position              []string `json:"position"`
			Priority              int      `json:"priority"`
			IsDynamicGeofilter    bool     `json:"is_dynamic_geofilter"`
			IsSponsored           bool     `json:"is_sponsored"`
			SponsoredSlugPosition string   `json:"sponsored_slug_position"`
			SponsoredSlug         struct {
				Alignment         string `json:"alignment"`
				Position          string `json:"position"`
				Text              string `json:"text"`
				TimeBeforeFadeout int    `json:"time_before_fadeout"`
			} `json:"sponsored_slug"`
			HideSponsoredSlug bool `json:"hide_sponsored_slug"`
			IsFeatured        bool `json:"is_featured"`
			IsLens            bool `json:"is_lens"`
			LensData          struct {
				Code         string `json:"code"`
				IconLink     string `json:"icon_link"`
				LensLink     string `json:"lens_link"`
				LensChecksum string `json:"lens_checksum"`
				HintID       string `json:"hint_id"`
				ConfigPath   string `json:"config_path"`
			} `json:"lens_data"`
		} `json:"2015-10-25T00:00-0700"`
		Two0151023T00000700 []struct {
			FilterID              string   `json:"filter_id"`
			Image                 string   `json:"image"`
			Position              []string `json:"position"`
			Priority              int      `json:"priority"`
			IsDynamicGeofilter    bool     `json:"is_dynamic_geofilter"`
			IsSponsored           bool     `json:"is_sponsored"`
			SponsoredSlugPosition string   `json:"sponsored_slug_position"`
			SponsoredSlug         struct {
				Alignment         string `json:"alignment"`
				Position          string `json:"position"`
				Text              string `json:"text"`
				TimeBeforeFadeout int    `json:"time_before_fadeout"`
			} `json:"sponsored_slug"`
			HideSponsoredSlug bool `json:"hide_sponsored_slug"`
			IsFeatured        bool `json:"is_featured"`
			IsLens            bool `json:"is_lens"`
			LensData          struct {
				Code         string `json:"code"`
				IconLink     string `json:"icon_link"`
				LensLink     string `json:"lens_link"`
				LensChecksum string `json:"lens_checksum"`
				HintID       string `json:"hint_id"`
				ConfigPath   string `json:"config_path"`
			} `json:"lens_data"`
		} `json:"2015-10-23T00:00-0700"`
		Two0151020T00000700 []struct {
			FilterID              string   `json:"filter_id"`
			Image                 string   `json:"image"`
			Position              []string `json:"position"`
			Priority              int      `json:"priority"`
			IsDynamicGeofilter    bool     `json:"is_dynamic_geofilter"`
			IsSponsored           bool     `json:"is_sponsored"`
			SponsoredSlugPosition string   `json:"sponsored_slug_position"`
			SponsoredSlug         struct {
				Alignment         string `json:"alignment"`
				Position          string `json:"position"`
				Text              string `json:"text"`
				TimeBeforeFadeout int    `json:"time_before_fadeout"`
			} `json:"sponsored_slug"`
			HideSponsoredSlug bool `json:"hide_sponsored_slug"`
			IsFeatured        bool `json:"is_featured"`
			IsLens            bool `json:"is_lens"`
			LensData          struct {
				Code         string `json:"code"`
				IconLink     string `json:"icon_link"`
				LensLink     string `json:"lens_link"`
				LensChecksum string `json:"lens_checksum"`
				HintID       string `json:"hint_id"`
				ConfigPath   string `json:"config_path"`
			} `json:"lens_data"`
		} `json:"2015-10-20T00:00-0700"`
		Two0151022T00000700 []struct {
			FilterID              string   `json:"filter_id"`
			Image                 string   `json:"image"`
			Position              []string `json:"position"`
			Priority              int      `json:"priority"`
			IsDynamicGeofilter    bool     `json:"is_dynamic_geofilter"`
			IsSponsored           bool     `json:"is_sponsored"`
			SponsoredSlugPosition string   `json:"sponsored_slug_position"`
			SponsoredSlug         struct {
				Alignment         string `json:"alignment"`
				Position          string `json:"position"`
				Text              string `json:"text"`
				TimeBeforeFadeout int    `json:"time_before_fadeout"`
			} `json:"sponsored_slug"`
			HideSponsoredSlug bool `json:"hide_sponsored_slug"`
			IsFeatured        bool `json:"is_featured"`
			IsLens            bool `json:"is_lens"`
			LensData          struct {
				Code         string `json:"code"`
				IconLink     string `json:"icon_link"`
				LensLink     string `json:"lens_link"`
				LensChecksum string `json:"lens_checksum"`
				HintID       string `json:"hint_id"`
				ConfigPath   string `json:"config_path"`
			} `json:"lens_data"`
		} `json:"2015-10-22T00:00-0700"`
		Two0151018T00000700 []struct {
			FilterID              string   `json:"filter_id"`
			Image                 string   `json:"image"`
			Position              []string `json:"position"`
			Priority              int      `json:"priority"`
			IsDynamicGeofilter    bool     `json:"is_dynamic_geofilter"`
			IsSponsored           bool     `json:"is_sponsored"`
			SponsoredSlugPosition string   `json:"sponsored_slug_position"`
			SponsoredSlug         struct {
				Alignment         string `json:"alignment"`
				Position          string `json:"position"`
				Text              string `json:"text"`
				TimeBeforeFadeout int    `json:"time_before_fadeout"`
			} `json:"sponsored_slug"`
			HideSponsoredSlug bool `json:"hide_sponsored_slug"`
			IsFeatured        bool `json:"is_featured"`
			IsLens            bool `json:"is_lens"`
			LensData          struct {
				Code         string `json:"code"`
				IconLink     string `json:"icon_link"`
				LensLink     string `json:"lens_link"`
				LensChecksum string `json:"lens_checksum"`
				HintID       string `json:"hint_id"`
				ConfigPath   string `json:"config_path"`
			} `json:"lens_data"`
		} `json:"2015-10-18T00:00-0700"`
		Two0151026T00000700 []struct {
			FilterID              string   `json:"filter_id"`
			Image                 string   `json:"image"`
			Position              []string `json:"position"`
			Priority              int      `json:"priority"`
			IsDynamicGeofilter    bool     `json:"is_dynamic_geofilter"`
			IsSponsored           bool     `json:"is_sponsored"`
			SponsoredSlugPosition string   `json:"sponsored_slug_position"`
			SponsoredSlug         struct {
				Alignment         string `json:"alignment"`
				Position          string `json:"position"`
				Text              string `json:"text"`
				TimeBeforeFadeout int    `json:"time_before_fadeout"`
			} `json:"sponsored_slug"`
			HideSponsoredSlug bool `json:"hide_sponsored_slug"`
			IsFeatured        bool `json:"is_featured"`
			IsLens            bool `json:"is_lens"`
			LensData          struct {
				Code         string `json:"code"`
				IconLink     string `json:"icon_link"`
				LensLink     string `json:"lens_link"`
				LensChecksum string `json:"lens_checksum"`
				HintID       string `json:"hint_id"`
				ConfigPath   string `json:"config_path"`
			} `json:"lens_data"`
		} `json:"2015-10-26T00:00-0700"`
		Two0151019T00000700 []struct {
			FilterID              string   `json:"filter_id"`
			Image                 string   `json:"image"`
			Position              []string `json:"position"`
			Priority              int      `json:"priority"`
			IsDynamicGeofilter    bool     `json:"is_dynamic_geofilter"`
			IsSponsored           bool     `json:"is_sponsored"`
			SponsoredSlugPosition string   `json:"sponsored_slug_position"`
			SponsoredSlug         struct {
				Alignment         string `json:"alignment"`
				Position          string `json:"position"`
				Text              string `json:"text"`
				TimeBeforeFadeout int    `json:"time_before_fadeout"`
			} `json:"sponsored_slug"`
			HideSponsoredSlug bool `json:"hide_sponsored_slug"`
			IsFeatured        bool `json:"is_featured"`
			IsLens            bool `json:"is_lens"`
			LensData          struct {
				Code         string `json:"code"`
				IconLink     string `json:"icon_link"`
				LensLink     string `json:"lens_link"`
				LensChecksum string `json:"lens_checksum"`
				HintID       string `json:"hint_id"`
				ConfigPath   string `json:"config_path"`
			} `json:"lens_data"`
		} `json:"2015-10-19T00:00-0700"`
		Two0151021T00000700 []struct {
			FilterID              string   `json:"filter_id"`
			Image                 string   `json:"image"`
			Position              []string `json:"position"`
			Priority              int      `json:"priority"`
			IsDynamicGeofilter    bool     `json:"is_dynamic_geofilter"`
			IsSponsored           bool     `json:"is_sponsored"`
			SponsoredSlugPosition string   `json:"sponsored_slug_position"`
			SponsoredSlug         struct {
				Alignment         string `json:"alignment"`
				Position          string `json:"position"`
				Text              string `json:"text"`
				TimeBeforeFadeout int    `json:"time_before_fadeout"`
			} `json:"sponsored_slug"`
			HideSponsoredSlug bool `json:"hide_sponsored_slug"`
			IsFeatured        bool `json:"is_featured"`
			IsLens            bool `json:"is_lens"`
			LensData          struct {
				Code         string `json:"code"`
				IconLink     string `json:"icon_link"`
				LensLink     string `json:"lens_link"`
				LensChecksum string `json:"lens_checksum"`
				ConfigPath   string `json:"config_path"`
			} `json:"lens_data"`
		} `json:"2015-10-21T00:00-0700"`
	} `json:"schedule"`
}

// Friend holds data about a Snapchat friend action.
type Friend struct {
	Message string `json:"message"`
	Param   string `json:"param"`
	Object  struct {
		Name                string   `json:"name"`
		UserID              string   `json:"user_id"`
		Type                int      `json:"type"`
		Display             string   `json:"display"`
		Ts                  int      `json:"ts"`
		Direction           string   `json:"direction"`
		CanSeeCustomStories bool     `json:"can_see_custom_stories"`
		Expiration          int      `json:"expiration"`
		FriendmojiString    string   `json:"friendmoji_string"`
		NeedsLove           bool     `json:"needs_love"`
		FriendmojiSymbols   []string `json:"friendmoji_symbols"`
		SnapStreakCount     int      `json:"snap_streak_count"`
	} `json:"object"`
	Logged bool `json:"logged"`
}

// SnapTag holds Snaptag data about a single Snaptag. Could be either a base64'd PNG or SVG image.
type SnapTag struct {
	Imagedata string `json:"imageData"`
	Qrpath    string `json:"qrPath"`
}

// SuggestedFriends holds results of suggested friends Snapchat recommends to you.
type SuggestedFriends struct {
	SuggestedFriendResults []interface{} `json:"suggested_friend_results"`
}
