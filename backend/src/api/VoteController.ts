import {Router} from 'express';
import VoteManager from '../managers/VoteManager';
import {Logger} from 'winston';
import {APIRequest, APIResponse, validate} from './ApiMiddleware';
import Joi from 'joi';
import {VoteSetRequest, VoteSetResponse} from './types/requests/VoteSet';
import {VoteListRequest, VoteListResponse} from './types/requests/VoteList';
import {VoteListItemEntity} from './types/entities/VoteEntity';
import UserManager from '../managers/UserManager';
import rateLimit from 'express-rate-limit';
import {RateLimiterMemory} from 'rate-limiter-flexible';
import {OAuth2ScopeEndpointsMap} from './utils/OAuth2-scopes';

export default class VoteController {
    public router = Router();
    private voteManager: VoteManager;
    private userManager: UserManager;
    private logger: Logger;

    // 60 requests per two minutes
    private readonly voteRateLimiter = rateLimit({
        max: 60,
        windowMs: 2 * 60 * 1000,
        skipSuccessfulRequests: false,
        standardHeaders: false,
        legacyHeaders: false,
        keyGenerator: (req) => String(req.session.data?.userId)
    });

    private readonly voteDailyRateLimiter = new RateLimiterMemory({
        points: 100,
        duration: 24 * 60 * 60, // Per day
    });

    private readonly commentVoteHourlyRateLimiter = new RateLimiterMemory({
        points: 30,
        duration: 60 * 60, // Per hour
    });

    constructor(voteManager: VoteManager, userManager: UserManager, oauthMiddlewareGenerator, logger: Logger) {
        this.voteManager = voteManager;
        this.userManager = userManager;
        this.logger = logger;

        const voteSchema = Joi.object<VoteSetRequest>({
            type: Joi.valid('post', 'comment', 'user').required(),
            id: Joi.number().required(),
            vote: Joi.number().required()
        });
        const listSchema = Joi.object<VoteListRequest>({
            type: Joi.valid('post', 'comment', 'user').required(),
            id: Joi.number().required()
        });

        this.router.post('/vote/set', this.voteRateLimiter, validate(voteSchema), oauthMiddlewareGenerator({scope: OAuth2ScopeEndpointsMap['/vote/set']}), (req, res) => this.setVote(req, res));
        this.router.post('/vote/list', validate(listSchema), oauthMiddlewareGenerator({scope: OAuth2ScopeEndpointsMap['/vote/list']}), (req, res) => this.list(req, res));
    }

    async setVote(request: APIRequest<VoteSetRequest>, response: APIResponse<VoteSetResponse>) {
        if (!request.session.data.userId) {
            return response.authRequired();
        }

        const userId = request.session.data.userId;
        const {id, type, vote} = request.body;

        const restrictions = await this.userManager.getUserRestrictions(userId);
        if ((type === 'user' && !restrictions.canVoteKarma) || (type !== 'user' && !restrictions.canVote)) {
            return response.error('cant-vote', 'Voting is disabled', 403);
        }

        try {
            const max = type === 'user' ? 2 : 1;
            const rangedVote = Math.max(Math.min(vote, max), -max);

            const targetUserId = await this.voteManager.getUserIdByVote(id, type);
            if (targetUserId && type !== 'user') {
                const voteKey = `${userId}:${targetUserId}`;
                try {
                    await this.voteDailyRateLimiter.consume(voteKey);
                    if (rangedVote < 0) {
                        await this.commentVoteHourlyRateLimiter.consume(voteKey);
                    }
                } catch (err) {
                    return response.error('too-many-votes', 'Too many votes', 403);
                }
            }

            let rating;
            switch (type) {
                case 'post':
                    rating = await this.voteManager.postVote(id, rangedVote, userId);
                    break;
                case 'comment':
                    rating = await this.voteManager.commentVote(id, rangedVote, userId);
                    break;
                case 'user':
                    rating = await this.voteManager.userVote(id, rangedVote, userId);
                    break;
                default:
                    return response.error('wrong-type', 'Wrong type', 401);
            }

            this.logger.info(`User #${userId} voted on ${type} with ${vote}`, { vote: vote, type: type, user_id: userId, item_id: id });

            response.success({
                type: type,
                id: id,
                rating: rating,
                vote: vote
            });
        }

        catch (err) {
            this.logger.error('Vote error', { error: err, user_id: userId, vote: vote, type: type, item_id: id });
            return response.error('error', 'Unknown error', 500);
        }
    }

    async list(request: APIRequest<VoteListRequest>, response: APIResponse<VoteListResponse>) {
        if (!request.session.data.userId) {
            return response.authRequired();
        }

        const {id, type} = request.body;

        try {
            let votes: VoteListItemEntity[];
            switch (type) {
                case 'post':
                    votes = await this.voteManager.getPostVotes(id);
                    break;
                case 'comment':
                    votes = await this.voteManager.getCommentVotes(id);
                    break;
                case 'user':
                    votes = await this.voteManager.getUserVotes(id);
                    break;
                default:
                    return response.error('wrong-type', 'Wrong type', 401);
            }

            response.success({votes});
        }
        catch (err) {
            this.logger.error('Vote list error', { error: err, type: type, item_id: id });
            return response.error('error', 'Unknown error', 500);
        }
    }
}
